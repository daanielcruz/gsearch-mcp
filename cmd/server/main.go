package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ─── constants ───

const (
	clientID     = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
	clientSecret = "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"
	tokenURL     = "https://oauth2.googleapis.com/token"
	endpoint     = "https://cloudcode-pa.googleapis.com/v1internal"
	primaryModel  = "gemini-3-flash-preview"
	fallbackModel = "gemini-2.5-flash"
	maxRetries      = 4
	defaultRetryDelay = 2 * time.Second
)

// ─── oauth creds ───

type oauthCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiryDate   int64  `json:"expiry_date"`
	IDToken      string `json:"id_token"`
}

func credsFiles() []string {
	home, _ := os.UserHomeDir()
	return []string{
		filepath.Join(home, ".gsearch", "oauth_creds.json"),
		filepath.Join(home, ".gemini", "oauth_creds.json"),
	}
}

func loadCreds() (*oauthCreds, string, error) {
	for _, p := range credsFiles() {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var c oauthCreds
		if err := json.Unmarshal(data, &c); err != nil {
			continue
		}
		return &c, p, nil
	}
	return nil, "", fmt.Errorf("no OAuth credentials found — run gsearch installer or gemini CLI first")
}

func saveCreds(path string, c *oauthCreds) error {
	data, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(path, data, 0600)
}

func isExpired(c *oauthCreds) bool {
	return time.Now().UnixMilli() > c.ExpiryDate-60000
}

func refreshToken(c *oauthCreds) error {
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"refresh_token": {c.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	resp, err := http.PostForm(tokenURL, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if tok, ok := result["access_token"].(string); ok {
		c.AccessToken = tok
	} else {
		return fmt.Errorf("no access_token in refresh response")
	}
	if exp, ok := result["expires_in"].(float64); ok {
		c.ExpiryDate = time.Now().UnixMilli() + int64(exp)*1000
	}
	if rt, ok := result["refresh_token"].(string); ok {
		c.RefreshToken = rt
	}
	if idt, ok := result["id_token"].(string); ok {
		c.IDToken = idt
	}
	return nil
}

func getToken() (string, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	creds, path, err := loadCreds()
	if err != nil {
		return "", err
	}
	if isExpired(creds) {
		if err := refreshToken(creds); err != nil {
			return "", fmt.Errorf("token refresh failed: %w", err)
		}
		if err := saveCreds(path, creds); err != nil {
			fmt.Fprintf(os.Stderr, "gsearch: warning: could not save refreshed token: %v\n", err)
		}
	}
	return creds.AccessToken, nil
}

// ─── project ID ───

func loadProject(token string) (string, error) {
	if p := os.Getenv("GSEARCH_PROJECT"); p != "" {
		return p, nil
	}

	body := []byte(`{"cloudaicompanionProject":""}`)
	req, _ := http.NewRequest("POST", endpoint+":loadCodeAssist", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("loadCodeAssist %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)
	if id, ok := result["cloudaicompanionProject"].(string); ok && id != "" {
		return id, nil
	}

	// check for ineligible tiers with validation required
	if tiers, ok := result["ineligibleTiers"].([]any); ok {
		for _, t := range tiers {
			tier, _ := t.(map[string]any)
			if reason, _ := tier["reasonCode"].(string); reason == "VALIDATION_REQUIRED" {
				msg, _ := tier["reasonMessage"].(string)
				url, _ := tier["validationUrl"].(string)
				if url != "" {
					return "", fmt.Errorf("account needs verification: %s\nVerify at: %s", msg, url)
				}
				return "", fmt.Errorf("account needs verification: %s", msg)
			}
			if reason, _ := tier["reasonMessage"].(string); reason != "" {
				return "", fmt.Errorf("ineligible: %s", reason)
			}
		}
	}

	// free-tier is allowed but no project yet — onboard automatically
	if hasTier(result, "allowedTiers", "free-tier") {
		id, err := onboardUser(token, "free-tier")
		if err != nil {
			return "", fmt.Errorf("onboarding failed: %w", err)
		}
		return id, nil
	}

	return "", fmt.Errorf("project ID not found — run 'gemini' CLI first to provision your account, or set GSEARCH_PROJECT env var")
}

func hasTier(result map[string]any, field, tierID string) bool {
	tiers, ok := result[field].([]any)
	if !ok {
		return false
	}
	for _, t := range tiers {
		tier, _ := t.(map[string]any)
		if id, _ := tier["id"].(string); id == tierID {
			return true
		}
	}
	return false
}

func onboardUser(token, tierID string) (string, error) {
	reqBody := map[string]any{
		"tierId": tierID,
		"metadata": map[string]any{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", endpoint+":onboardUser", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("onboardUser %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)

	opName, _ := result["name"].(string)
	if opName == "" {
		return "", fmt.Errorf("no operation name in onboardUser response")
	}

	return pollOperation(token, opName)
}

func pollOperation(token, opName string) (string, error) {
	opURL := endpoint + "/" + opName
	client := &http.Client{Timeout: 15 * time.Second}

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", opURL, nil)
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var result map[string]any
		json.Unmarshal(body, &result)

		if done, _ := result["done"].(bool); done {
			response, _ := result["response"].(map[string]any)
			project, _ := response["cloudaicompanionProject"].(map[string]any)
			if id, _ := project["id"].(string); id != "" {
				return id, nil
			}
			return "", fmt.Errorf("onboarding completed but no project ID in response")
		}

		time.Sleep(2 * time.Second)
	}

	return "", fmt.Errorf("onboarding timeout — operation did not complete")
}

// ─── google search ───

func parseRetryDelay(body []byte) time.Duration {
	var errResp map[string]any
	if json.Unmarshal(body, &errResp) != nil {
		return defaultRetryDelay
	}
	errObj, _ := errResp["error"].(map[string]any)
	details, _ := errObj["details"].([]any)
	for _, d := range details {
		detail, _ := d.(map[string]any)
		if retryInfo, ok := detail["retryDelay"].(string); ok {
			retryInfo = strings.TrimSuffix(retryInfo, "s")
			if secs, err := strconv.ParseFloat(retryInfo, 64); err == nil {
				delay := time.Duration(secs*1000) * time.Millisecond
				if delay < 500*time.Millisecond {
					delay = 500 * time.Millisecond
				}
				if delay > 30*time.Second {
					delay = 30 * time.Second
				}
				return delay
			}
		}
	}
	return defaultRetryDelay
}

func doSearch(ctx context.Context, query, modelName, token, project string) (string, int, time.Duration, error) {
	reqBody := map[string]any{
		"model":          modelName,
		"project":        project,
		"user_prompt_id": uuid.New().String(),
		"request": map[string]any{
			"contents":        []map[string]any{{"role": "user", "parts": []map[string]any{{"text": query}}}},
			"tools":           []map[string]any{{"googleSearch": map[string]any{}}},
			"generationConfig": map[string]any{"temperature": 0, "topP": 1},
			"session_id":      cachedSessionID,
		},
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, _ := http.NewRequestWithContext(ctx, "POST", endpoint+":generateContent", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == 429 {
		delay := parseRetryDelay(respBody)
		return "", 429, delay, fmt.Errorf("rate limited")
	}

	if resp.StatusCode != 200 {
		return "", resp.StatusCode, 0, fmt.Errorf("API %d: %s", resp.StatusCode, truncate(string(respBody), 300))
	}

	text, err := parseResponse(respBody)
	return text, 200, 0, err
}

func googleSearch(ctx context.Context, query string) (string, error) {
	token, err := getToken()
	if err != nil {
		return "", err
	}

	// cache project on first call (retries on failure)
	projectMu.Lock()
	if cachedProject == "" {
		p, err := loadProject(token)
		if err != nil {
			projectMu.Unlock()
			return "", fmt.Errorf("project: %w", err)
		}
		cachedProject = p
	}
	project := cachedProject
	projectMu.Unlock()

	// try primary model with retry + fallback
	var lastErr error
	models := []string{primaryModel, fallbackModel}
	for _, m := range models {
		for attempt := 0; attempt < maxRetries; attempt++ {
			text, status, retryAfter, err := doSearch(ctx, query, m, token, project)
			if status == 200 {
				return text, nil
			}
			if status == 429 {
				if attempt < maxRetries-1 {
					time.Sleep(retryAfter)
					continue
				}
				break // try fallback model
			}
			// non-429 error (500, 403, network) — try fallback model
			lastErr = err
			break
		}
	}

	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("all models exhausted — try again shortly")
}

func parseResponse(data []byte) (string, error) {
	var raw map[string]any
	json.Unmarshal(data, &raw)

	inner, ok := raw["response"].(map[string]any)
	if !ok {
		inner = raw
	}

	candidates, _ := inner["candidates"].([]any)
	if len(candidates) == 0 {
		return "No results", nil
	}

	candidate, _ := candidates[0].(map[string]any)
	content, _ := candidate["content"].(map[string]any)
	parts, _ := content["parts"].([]any)

	var text string
	for _, p := range parts {
		part, _ := p.(map[string]any)
		if t, ok := part["text"].(string); ok {
			text += t
		}
	}

	// extract sources
	grounding, _ := candidate["groundingMetadata"].(map[string]any)
	chunks, _ := grounding["groundingChunks"].([]any)

	type source struct {
		title string
		url   string
	}
	var sources []source
	for _, c := range chunks {
		chunk, _ := c.(map[string]any)
		web, ok := chunk["web"].(map[string]any)
		if !ok || web == nil {
			continue
		}
		sources = append(sources, source{
			title: getString(web, "title"),
			url:   getString(web, "uri"),
		})
	}

	// insert citation markers
	supports, _ := grounding["groundingSupports"].([]any)
	if len(supports) > 0 && len(chunks) > 0 {
		type insertion struct {
			pos    int
			marker string
		}
		var insertions []insertion
		for _, s := range supports {
			sup, _ := s.(map[string]any)
			segment, _ := sup["segment"].(map[string]any)
			indices, _ := sup["groundingChunkIndices"].([]any)
			if len(indices) > 0 {
				var marker string
				for _, idx := range indices {
					if n, ok := idx.(float64); ok {
						marker += fmt.Sprintf("[%d]", int(n)+1)
					}
				}
				endIdx := 0
				if n, ok := segment["endIndex"].(float64); ok {
					endIdx = int(n)
				}
				insertions = append(insertions, insertion{endIdx, marker})
			}
		}
		// sort desc
		for i := 0; i < len(insertions); i++ {
			for j := i + 1; j < len(insertions); j++ {
				if insertions[j].pos > insertions[i].pos {
					insertions[i], insertions[j] = insertions[j], insertions[i]
				}
			}
		}
		runes := []rune(text)
		for _, ins := range insertions {
			pos := ins.pos
			if pos > len(runes) {
				pos = len(runes)
			}
			markerRunes := []rune(ins.marker)
			result := make([]rune, 0, len(runes)+len(markerRunes))
			result = append(result, runes[:pos]...)
			result = append(result, markerRunes...)
			result = append(result, runes[pos:]...)
			runes = result
		}
		text = string(runes)
	}

	// append sources list
	if len(sources) > 0 {
		text += "\n\nSources:\n"
		for i, s := range sources {
			text += fmt.Sprintf("[%d] %s (%s)\n", i+1, s.title, s.url)
		}
	}

	return text, nil
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// ─── MCP server ───

// cached per-process
var (
	cachedProject   string
	projectMu       sync.Mutex
	tokenMu         sync.Mutex
	cachedSessionID = uuid.New().String()
)

func main() {
	s := server.NewMCPServer(
		"gsearch",
		"1.0.0",
		server.WithToolCapabilities(false),
	)

	tool := mcp.NewTool("google_search",
		mcp.WithDescription("Search the web using Google Search grounding. Returns an answer with inline citations and source URLs. Use for current events, documentation, news, or any real-time web information.\n\nResponse time: 2-15s typical, up to 60s with retries. On 429 the server retries automatically with dynamic backoff (typically 2s) and falls back to an alternate model. Avoid calling this tool in rapid succession — batch your search needs into a single, well-crafted query when possible."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("The search query — be specific and concise for best results"),
		),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
	)

	s.AddTool(tool, searchHandler)

	if err := server.ServeStdio(s); err != nil {
		fmt.Fprintf(os.Stderr, "gsearch: %v\n", err)
		os.Exit(1)
	}
}

func searchHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	query, err := request.RequireString("query")
	if err != nil {
		return mcp.NewToolResultError("missing required parameter: query"), nil
	}

	result, err := googleSearch(ctx, query)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("search error: %v", err)), nil
	}

	return mcp.NewToolResultText(result), nil
}
