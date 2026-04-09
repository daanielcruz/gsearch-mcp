package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
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
	maxAttempts       = 10
	initialDelay      = 1 * time.Second
	maxDelay          = 30 * time.Second
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
	envProject := os.Getenv("GSEARCH_PROJECT")
	if envProject == "" {
		envProject = os.Getenv("GOOGLE_CLOUD_PROJECT")
	}
	if envProject == "" {
		envProject = os.Getenv("GOOGLE_CLOUD_PROJECT_ID")
	}
	if envProject != "" {
		return envProject, nil
	}

	loadReq := map[string]any{
		"cloudaicompanionProject": "",
		"metadata": map[string]any{
			"ideType":    "GEMINI_CLI",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	body, _ := json.Marshal(loadReq)
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

	// already provisioned
	if id, ok := result["cloudaicompanionProject"].(string); ok && id != "" {
		return id, nil
	}

	// check for validation required
	if tiers, ok := result["ineligibleTiers"].([]any); ok {
		for _, t := range tiers {
			tier, _ := t.(map[string]any)
			if reason, _ := tier["reasonCode"].(string); reason == "VALIDATION_REQUIRED" {
				msg, _ := tier["reasonMessage"].(string)
				vurl, _ := tier["validationUrl"].(string)
				if vurl != "" {
					return "", fmt.Errorf("account needs verification: %s\nVerify at: %s", msg, vurl)
				}
				return "", fmt.Errorf("account needs verification: %s", msg)
			}
		}
	}

	// find the default onboarding tier (mirrors Gemini CLI's getOnboardTier)
	tier := getDefaultTier(result)
	if tier == nil {
		return "", fmt.Errorf("no eligible tier found — set GSEARCH_PROJECT or GOOGLE_CLOUD_PROJECT env var")
	}

	tierID, _ := tier["id"].(string)
	needsProject, _ := tier["userDefinedCloudaicompanionProject"].(bool)

	if needsProject {
		return "", fmt.Errorf("this account requires GSEARCH_PROJECT or GOOGLE_CLOUD_PROJECT env var (tier: %s)", tierID)
	}

	// onboard with the default tier
	id, err := onboardUser(token, tierID, "")
	if err != nil {
		return "", fmt.Errorf("onboarding failed: %w", err)
	}
	return id, nil
}

func getDefaultTier(result map[string]any) map[string]any {
	tiers, ok := result["allowedTiers"].([]any)
	if !ok {
		return nil
	}
	for _, t := range tiers {
		tier, _ := t.(map[string]any)
		if isDefault, _ := tier["isDefault"].(bool); isDefault {
			return tier
		}
	}
	// fallback: first tier
	if len(tiers) > 0 {
		tier, _ := tiers[0].(map[string]any)
		return tier
	}
	return nil
}

func onboardUser(token, tierID, projectID string) (string, error) {
	reqBody := map[string]any{
		"tierId": tierID,
		"metadata": map[string]any{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	if projectID != "" {
		reqBody["cloudaicompanionProject"] = projectID
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

// error classification for retry logic (mirrors Gemini CLI)
const (
	errRetryable = iota // retry with backoff (per-minute limit, 503, network)
	errTerminal         // switch model immediately (daily limit, quota exhausted)
	errFatal            // stop entirely (400, 401)
)

type searchError struct {
	status   int
	kind     int // errRetryable, errTerminal, errFatal
	delay    time.Duration
	message  string
}

func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "ms") {
		if ms, err := strconv.ParseFloat(strings.TrimSuffix(s, "ms"), 64); err == nil {
			return time.Duration(ms) * time.Millisecond
		}
	}
	if strings.HasSuffix(s, "s") {
		if secs, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64); err == nil {
			return time.Duration(secs*1000) * time.Millisecond
		}
	}
	return 0
}

func classifyError(statusCode int, body []byte) searchError {
	se := searchError{status: statusCode, kind: errRetryable, delay: defaultRetryDelay}

	// fatal: don't retry
	if statusCode == 400 || statusCode == 401 || statusCode == 403 {
		se.kind = errFatal
		se.message = fmt.Sprintf("API %d: %s", statusCode, truncate(string(body), 300))
		return se
	}

	// 404: model not found → switch model
	if statusCode == 404 {
		se.kind = errTerminal
		se.message = "model not found"
		return se
	}

	// 503: retryable server error
	if statusCode == 503 {
		se.kind = errRetryable
		se.message = "service unavailable"
		return se
	}

	// 429/499: parse error details to classify
	if statusCode != 429 && statusCode != 499 {
		se.message = fmt.Sprintf("API %d: %s", statusCode, truncate(string(body), 300))
		return se
	}

	var errResp map[string]any
	if json.Unmarshal(body, &errResp) != nil {
		se.message = "rate limited"
		return se
	}

	errObj, _ := errResp["error"].(map[string]any)
	details, _ := errObj["details"].([]any)

	// collect all details before deciding (avoid early return missing RetryInfo)
	for _, d := range details {
		detail, _ := d.(map[string]any)
		dtype, _ := detail["@type"].(string)

		switch dtype {
		case "type.googleapis.com/google.rpc.ErrorInfo":
			reason, _ := detail["reason"].(string)
			switch reason {
			case "QUOTA_EXHAUSTED", "INSUFFICIENT_G1_CREDITS_BALANCE":
				se.kind = errTerminal
				se.message = "quota exhausted"
			case "RATE_LIMIT_EXCEEDED":
				se.kind = errRetryable
				se.message = "rate limited"
			}

		case "type.googleapis.com/google.rpc.QuotaFailure":
			violations, _ := detail["violations"].([]any)
			for _, v := range violations {
				viol, _ := v.(map[string]any)
				quotaID, _ := viol["quotaId"].(string)
				if strings.Contains(quotaID, "PerDay") || strings.Contains(quotaID, "Daily") {
					se.kind = errTerminal
					se.message = "daily quota exhausted"
				}
			}

		case "type.googleapis.com/google.rpc.RetryInfo":
			if rd, ok := detail["retryDelay"].(string); ok {
				if d := parseDuration(rd); d > 0 {
					se.delay = d
					if d > 5*time.Minute {
						se.kind = errTerminal
						se.message = "rate limited (long delay)"
					}
				}
			}
		}
	}

	// clamp only the default delay, not API-provided delays
	if se.delay == defaultRetryDelay {
		if se.delay < 500*time.Millisecond {
			se.delay = 500 * time.Millisecond
		}
	}
	if se.message == "" {
		se.message = "rate limited"
	}
	return se
}

func doSearch(ctx context.Context, query, modelName, token, project string) (string, int, searchError, error) {
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
		return "", 0, searchError{kind: errRetryable, message: err.Error()}, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		se := classifyError(resp.StatusCode, respBody)
		return "", resp.StatusCode, se, fmt.Errorf("%s", se.message)
	}

	text, err := parseResponse(respBody)
	return text, 200, searchError{}, err
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

	// retry with exponential backoff + jitter, model fallback on terminal errors
	model := primaryModel
	var lastErr error
	delay := initialDelay
	consecutiveFails := 0

	for attempt := 0; attempt < maxAttempts; attempt++ {
		text, status, se, err := doSearch(ctx, query, model, token, project)
		if status == 200 {
			return text, nil
		}

		// check context cancellation immediately
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		lastErr = err
		consecutiveFails++

		// fatal: try token refresh on 401, otherwise stop
		if se.kind == errFatal {
			if status == 401 {
				if newToken, refreshErr := getToken(); refreshErr == nil {
					token = newToken
					consecutiveFails = 0
					fmt.Fprintf(os.Stderr, "gsearch: refreshed token after 401, retrying\n")
					continue
				}
			}
			return "", err
		}

		// terminal: switch model immediately
		if se.kind == errTerminal {
			if model == primaryModel {
				fmt.Fprintf(os.Stderr, "gsearch: terminal error on %s (%s), switching to fallback\n", model, se.message)
				model = fallbackModel
				consecutiveFails = 0
				delay = initialDelay
				continue
			}
			return "", fmt.Errorf("%s on all models", se.message)
		}

		// retryable: backoff with jitter
		if consecutiveFails >= 3 && model == primaryModel {
			fmt.Fprintf(os.Stderr, "gsearch: switching to fallback model after %d retryable failures\n", consecutiveFails)
			model = fallbackModel
			consecutiveFails = 0
			delay = initialDelay
		}

		// pick delay: exponential backoff for client delay, respect API delay without jitter
		wait := delay
		useAPIDelay := se.delay > wait && se.delay != defaultRetryDelay
		if useAPIDelay {
			wait = se.delay // respect API-provided delay as-is
		} else {
			// apply ±30% jitter only to client-side backoff
			jitter := 0.7 + rand.Float64()*0.6
			wait = time.Duration(float64(wait) * jitter)
			if wait > maxDelay {
				wait = maxDelay
			}
		}

		fmt.Fprintf(os.Stderr, "gsearch: attempt %d/%d failed (status %d, %s, model %s), retrying in %v\n",
			attempt+1, maxAttempts, status, se.message, model, wait.Round(time.Millisecond))

		// context-aware sleep
		if attempt < maxAttempts-1 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}

		// exponential increase for next iteration
		delay *= 2
		if delay > maxDelay {
			delay = maxDelay
		}
	}

	if lastErr != nil {
		return "", fmt.Errorf("all models exhausted after %d attempts (last: %v)", maxAttempts, lastErr)
	}
	return "", fmt.Errorf("all models exhausted after %d attempts", maxAttempts)
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
