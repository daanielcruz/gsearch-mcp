package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func geminiUserAgent(model string) string {
	if model == "" {
		model = defaultModel
	}
	return fmt.Sprintf("GeminiCLI/%s/%s (%s; %s; terminal)", geminiCLIVersion, model, runtime.GOOS, runtime.GOARCH)
}

func chromePlatform() string {
	switch runtime.GOOS {
	case "darwin":
		return `"macOS"`
	case "windows":
		return `"Windows"`
	default:
		return `"Linux"`
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ─── constants ───

const (
	clientID          = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
	clientSecret      = "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"
	tokenURL          = "https://oauth2.googleapis.com/token"
	oauthEndpoint     = "https://cloudcode-pa.googleapis.com/v1internal"
	apiKeyEndpoint    = "https://generativelanguage.googleapis.com/v1beta"
	defaultModel      = "gemini-3-flash-preview"
	fallbackModel     = "gemini-2.5-flash"
	geminiCLIVersion  = "0.40.0"
	agyClientID       = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	agyClientSecret   = "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"
	agyDailyEndpoint  = "https://daily-cloudcode-pa.googleapis.com/v1internal"
	agyProdEndpoint   = "https://cloudcode-pa.googleapis.com/v1internal"
	agyDefaultModel   = "gemini-3.5-flash-lite"
	agyCLIVersion     = "1.4.6"
	agyCLChangelist   = "1005129088"
	maxAttempts       = 10
	initialDelay      = 1 * time.Second
	maxDelay          = 30 * time.Second
	defaultRetryDelay = 2 * time.Second
)

const agySearchSystemInstruction = "You are a search engine bot. You will be given a query from a user. Your task is to search the web for relevant information that will help the user. You MUST perform a web search. Do not respond or interact with the user, please respond as if they typed the query into a search bar."

var markdownTitleEscaper = strings.NewReplacer(`\`, `\\`, `[`, `\[`, `]`, `\]`)

func markdownEscapeTitle(title string) string {
	return markdownTitleEscaper.Replace(title)
}

func agyUserAgentFor(goos, goarch string) string {
	if goarch != "arm64" {
		goarch = "amd64"
	}
	return fmt.Sprintf("antigravity/cli/%s (aidev_client; os_type=%s; arch=%s; cl=%s; auth_method=consumer)", agyCLIVersion, goos, goarch, agyCLChangelist)
}

func agyUserAgent() string {
	return agyUserAgentFor(runtime.GOOS, runtime.GOARCH)
}

func agyEndpoint() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("GSEARCH_ANTIGRAVITY_HOST")), "prod") {
		return agyProdEndpoint
	}
	return agyDailyEndpoint
}

// ─── oauth creds ───

type oauthCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiryDate   int64  `json:"expiry_date"`
	IDToken      string `json:"id_token"`
	Provider     string `json:"provider,omitempty"`
}

func (c *oauthCreds) antigravity() bool {
	return c != nil && c.Provider == "antigravity"
}

// currentProvider reporta o provider das credenciais em uso; chamadas concorrentes
// passam por tokenMu para não disputar a escrita de cachedCreds.
func currentProvider() string {
	tokenMu.Lock()
	defer tokenMu.Unlock()
	if cachedCreds != nil {
		return cachedCreds.Provider
	}
	return ""
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
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	// WriteFile only applies the mode when creating the file.
	return os.Chmod(path, 0600)
}

func isExpired(c *oauthCreds) bool {
	return time.Now().UnixMilli() > c.ExpiryDate-60000
}

func refreshToken(c *oauthCreds) error {
	id, secret := clientID, clientSecret
	if c.antigravity() {
		id, secret = agyClientID, agyClientSecret
	}
	form := url.Values{
		"client_id":     {id},
		"client_secret": {secret},
		"refresh_token": {c.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(tokenURL, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read token refresh response: %w", err)
	}
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

func getToken(rejectedToken string) (string, error) {
	tokenMu.Lock()
	defer tokenMu.Unlock()

	if cachedCreds != nil && !isExpired(cachedCreds) && cachedCreds.AccessToken != rejectedToken {
		return cachedCreds.AccessToken, nil
	}

	creds, path, err := loadCreds()
	if err != nil {
		return "", err
	}
	if isExpired(creds) || creds.AccessToken == rejectedToken {
		if err := refreshToken(creds); err != nil {
			return "", fmt.Errorf("token refresh failed: %w", err)
		}
		if err := saveCreds(path, creds); err != nil {
			fmt.Fprintf(os.Stderr, "gsearch: warning: could not save refreshed token: %v\n", err)
		}
	}
	cachedCreds = creds
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
	if configuredProject != "" {
		return configuredProject, nil
	}

	agy := currentProvider() == "antigravity"
	endpoint, ua := oauthEndpoint, geminiUserAgent("")
	var loadReq map[string]any
	if agy {
		endpoint, ua = agyEndpoint(), agyUserAgent()
		loadReq = map[string]any{
			"metadata": map[string]any{
				"ideType": "ANTIGRAVITY",
			},
		}
	} else {
		loadReq = map[string]any{
			"cloudaicompanionProject": "",
			"metadata": map[string]any{
				"ideType":    "IDE_UNSPECIFIED",
				"platform":   "PLATFORM_UNSPECIFIED",
				"pluginType": "GEMINI",
			},
		}
	}
	body, _ := json.Marshal(loadReq)
	req, _ := http.NewRequest("POST", endpoint+":loadCodeAssist", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read loadCodeAssist response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", searchError{status: resp.StatusCode, message: fmt.Sprintf("loadCodeAssist %d: %s", resp.StatusCode, truncate(string(respBody), 200))}
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode loadCodeAssist response: %w", err)
	}
	if err := responseError(result); err != nil {
		return "", err
	}

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
	agy := currentProvider() == "antigravity"
	endpoint, ua := oauthEndpoint, geminiUserAgent("")
	var reqBody map[string]any
	if agy {
		endpoint, ua = agyEndpoint(), agyUserAgent()
		reqBody = map[string]any{
			"tierId": tierID,
			"metadata": map[string]any{
				"ideType": "ANTIGRAVITY",
			},
		}
	} else {
		reqBody = map[string]any{
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
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", endpoint+":onboardUser", bytes.NewReader(bodyBytes))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", ua)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read onboardUser response: %w", err)
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("onboardUser %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode onboardUser response: %w", err)
	}
	if err := responseError(result); err != nil {
		return "", err
	}

	if done, _ := result["done"].(bool); done {
		return operationProject(result)
	}

	opName, _ := result["name"].(string)
	if opName == "" {
		return "", fmt.Errorf("no operation name in onboardUser response")
	}

	return pollOperation(token, opName)
}

func operationProject(result map[string]any) (string, error) {
	response, _ := result["response"].(map[string]any)
	project, _ := response["cloudaicompanionProject"].(map[string]any)
	if id, _ := project["id"].(string); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("onboarding completed but no project ID in response")
}

func pollOperation(token, opName string) (string, error) {
	opEndpoint, ua := oauthEndpoint, geminiUserAgent("")
	if currentProvider() == "antigravity" {
		opEndpoint, ua = agyEndpoint(), agyUserAgent()
	}
	opURL := opEndpoint + "/" + opName
	client := &http.Client{Timeout: 15 * time.Second}

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", opURL, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("User-Agent", ua)

		resp, err := client.Do(req)
		if err != nil {
			return "", err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return "", fmt.Errorf("read operation response: %w", err)
		}
		if resp.StatusCode != 200 {
			return "", fmt.Errorf("operation HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return "", fmt.Errorf("decode operation response: %w", err)
		}
		if err := responseError(result); err != nil {
			return "", err
		}

		if done, _ := result["done"].(bool); done {
			return operationProject(result)
		}

		time.Sleep(time.Second)
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
	status        int
	kind          int // errRetryable, errTerminal, errFatal
	delay         time.Duration
	explicitDelay bool
	message       string
}

func (se searchError) Error() string {
	return se.message
}

func parseDuration(s string) time.Duration {
	delay, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return delay
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

	// 503: switch model immediately
	if statusCode == 503 {
		se.kind = errTerminal
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
					se.explicitDelay = true
					if d > 5*time.Minute {
						se.kind = errTerminal
						se.message = "rate limited (long delay)"
					}
				}
			}
		}
	}

	if se.message == "" {
		se.message = "rate limited"
	}
	return se
}

func retryWait(delay time.Duration, se searchError) time.Duration {
	wait := time.Duration(float64(delay) * (0.7 + rand.Float64()*0.6))
	if wait > maxDelay {
		wait = maxDelay
	}
	if se.explicitDelay && se.delay > wait {
		wait = se.delay
	}
	return wait
}

func doSearch(ctx context.Context, query, modelName, token, project string) (string, int, searchError, error) {
	var requestURL string
	var bodyBytes []byte

	directBody := map[string]any{
		"contents": []map[string]any{{"role": "user", "parts": []map[string]any{{"text": query}}}},
		"systemInstruction": map[string]any{
			"parts": []map[string]any{{"text": agySearchSystemInstruction}},
		},
		"tools":            []map[string]any{{"googleSearch": map[string]any{}}},
		"generationConfig": map[string]any{"temperature": 0, "topP": 1},
	}

	agy := apiKey == "" && currentProvider() == "antigravity"
	if apiKey != "" {
		bodyBytes, _ = json.Marshal(directBody)
		requestURL = fmt.Sprintf("%s/models/%s:generateContent", apiKeyEndpoint, modelName)
	} else if agy {
		reqBody := map[string]any{
			"project":     project,
			"model":       modelName,
			"userAgent":   "antigravity",
			"requestType": "web_search",
			"request": map[string]any{
				"contents": []map[string]any{{"role": "user", "parts": []map[string]any{{"text": query}}}},
				"systemInstruction": map[string]any{
					"role":  "user",
					"parts": []map[string]any{{"text": agySearchSystemInstruction}},
				},
				"tools": []map[string]any{{"googleSearch": map[string]any{
					"enhancedContent": map[string]any{
						"imageSearch": map[string]any{"maxResultCount": 5},
					},
				}}},
				"generationConfig": map[string]any{"candidateCount": 1},
			},
		}
		bodyBytes, _ = json.Marshal(reqBody)
		requestURL = agyEndpoint() + ":generateContent"
	} else {
		reqBody := map[string]any{
			"model":          modelName,
			"project":        project,
			"user_prompt_id": uuid.New().String(),
			"request": map[string]any{
				"contents":          directBody["contents"],
				"systemInstruction": directBody["systemInstruction"],
				"tools":             directBody["tools"],
				"generationConfig":  directBody["generationConfig"],
				"session_id":        cachedSessionID,
			},
		}
		bodyBytes, _ = json.Marshal(reqBody)
		requestURL = oauthEndpoint + ":generateContent"
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", requestURL, bytes.NewReader(bodyBytes))
	if apiKey == "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("x-goog-api-key", apiKey)
	}
	req.Header.Set("Content-Type", "application/json")
	if agy {
		req.Header.Set("User-Agent", agyUserAgent())
	} else {
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", geminiUserAgent(modelName))
	}

	// wait for our turn
	select {
	case <-ctx.Done():
		return "", 0, searchError{kind: errRetryable, message: ctx.Err().Error()}, ctx.Err()
	case apiSem <- struct{}{}:
	}
	defer func() { <-apiSem }()

	// respect global cooldown if active
	cooldownMu.Lock()
	waitCooldown := time.Until(cooldownUntil)
	cooldownMu.Unlock()
	if waitCooldown > 0 {
		select {
		case <-ctx.Done():
			return "", 0, searchError{kind: errRetryable, message: ctx.Err().Error()}, ctx.Err()
		case <-time.After(waitCooldown):
		}
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, searchError{kind: errRetryable, message: err.Error()}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, searchError{kind: errRetryable, message: err.Error()}, fmt.Errorf("read search response: %w", err)
	}

	if resp.StatusCode != 200 {
		se := classifyError(resp.StatusCode, respBody)
		return "", resp.StatusCode, se, fmt.Errorf("%s", se.message)
	}

	text, err := parseResponse(respBody)
	return text, 200, searchError{}, err
}

func googleSearch(ctx context.Context, query string) (string, error) {
	var token, project string
	refreshedAfter401 := false

	if apiKey == "" {
		var err error
		token, err = getToken("")
		if err != nil {
			return "", err
		}

		projectMu.Lock()
		if cachedProject == "" {
			p, err := loadProject(token)
			var se searchError
			if errors.As(err, &se) && se.status == 401 && !refreshedAfter401 {
				refreshedAfter401 = true
				token, err = getToken(token)
				if err != nil {
					projectMu.Unlock()
					return "", fmt.Errorf("project token refresh: %w", err)
				}
				p, err = loadProject(token)
			}
			if err != nil {
				projectMu.Unlock()
				return "", fmt.Errorf("project: %w", err)
			}
			cachedProject = p
		}
		project = cachedProject
		projectMu.Unlock()
	}

	// retry with exponential backoff + jitter, model fallback on terminal errors
	modelList := models
	if len(modelList) == 0 {
		modelList = []string{defaultModel}
	}
	if apiKey == "" && currentProvider() == "antigravity" && !modelsConfigured {
		modelList = []string{agyDefaultModel}
	}
	modelIdx := 0
	model := modelList[0]
	var lastErr error
	delay := initialDelay
	consecutiveFails := 0

	for attempt := 0; attempt < maxAttempts; attempt++ {
		text, status, se, err := doSearch(ctx, query, model, token, project)
		if status == 200 {
			return text, err
		}

		// check context cancellation immediately
		if ctx.Err() != nil {
			return "", ctx.Err()
		}

		lastErr = err
		consecutiveFails++

		// fatal: try token refresh on 401, otherwise stop
		if se.kind == errFatal {
			if status == 401 && apiKey == "" && !refreshedAfter401 {
				refreshedAfter401 = true
				newToken, refreshErr := getToken(token)
				if refreshErr != nil {
					return "", fmt.Errorf("search token refresh: %w", refreshErr)
				}
				token = newToken
				consecutiveFails = 0
				fmt.Fprintf(os.Stderr, "gsearch: refreshed token after 401, retrying\n")
				continue
			}
			return "", err
		}

		// terminal: switch model immediately
		if se.kind == errTerminal {
			if modelIdx < len(modelList)-1 {
				modelIdx++
				model = modelList[modelIdx]
				fmt.Fprintf(os.Stderr, "gsearch: terminal error, switching to %s\n", model)
				consecutiveFails = 0
				delay = initialDelay
				continue
			}
			return "", fmt.Errorf("%s on all models", se.message)
		}

		// retryable: switch model after 3 consecutive failures
		if consecutiveFails >= 3 && modelIdx < len(modelList)-1 {
			modelIdx++
			model = modelList[modelIdx]
			fmt.Fprintf(os.Stderr, "gsearch: switching to %s after %d failures\n", model, consecutiveFails)
			consecutiveFails = 0
			delay = initialDelay
		}

		wait := retryWait(delay, se)

		cooldownMu.Lock()
		if time.Now().Add(wait).After(cooldownUntil) {
			cooldownUntil = time.Now().Add(wait)
		}
		cooldownMu.Unlock()

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

func responseError(result map[string]any) error {
	if errObj, ok := result["error"].(map[string]any); ok {
		return fmt.Errorf("API error %v: %s", errObj["code"], getString(errObj, "message"))
	}
	return nil
}

func parseResponse(data []byte) (string, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("decode search response: %w", err)
	}
	if err := responseError(raw); err != nil {
		return "", err
	}

	inner, ok := raw["response"].(map[string]any)
	if !ok {
		inner = raw
	}
	if err := responseError(inner); err != nil {
		return "", err
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
	var redirectURLs []string
	for _, c := range chunks {
		chunk, _ := c.(map[string]any)
		web, _ := chunk["web"].(map[string]any)
		redirectURLs = append(redirectURLs, getString(web, "uri"))
	}
	resolved := resolveRedirects(redirectURLs)

	var sources []source
	for i, c := range chunks {
		chunk, _ := c.(map[string]any)
		web, _ := chunk["web"].(map[string]any)
		title := getString(web, "title")
		if title == "" {
			title = "Untitled"
		}
		urlStr := resolved[i]
		if urlStr == "" {
			urlStr = "No URI"
		}
		sources = append(sources, source{title: title, url: urlStr})
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
		// sort asc
		sort.Slice(insertions, func(i, j int) bool {
			return insertions[i].pos < insertions[j].pos
		})

		var builder strings.Builder
		builder.Grow(len(text) + len(insertions)*10)
		lastPos := 0
		for _, ins := range insertions {
			pos := ins.pos
			if pos > len(text) {
				pos = len(text)
			}
			if pos < lastPos {
				pos = lastPos
			}
			builder.WriteString(text[lastPos:pos])
			builder.WriteString(ins.marker)
			lastPos = pos
		}
		builder.WriteString(text[lastPos:])
		text = builder.String()
	}

	// append sources list
	if len(sources) > 0 {
		var builder strings.Builder
		builder.Grow(len(text) + 200)
		builder.WriteString(text)
		builder.WriteString("\n\nSources:\n")
		for i, s := range sources {
			fmt.Fprintf(&builder, "[%d] [%s](%s)\n", i+1, markdownEscapeTitle(s.title), s.url)
		}
		text = builder.String()
	}

	return text, nil
}

func validSourceURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return ""
	}
	return parsed.String()
}

func googleRedirectURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	return host == "google.com" || strings.HasSuffix(host, ".google.com") ||
		host == "googleapis.com" || strings.HasSuffix(host, ".googleapis.com") ||
		host == "googleusercontent.com" || strings.HasSuffix(host, ".googleusercontent.com")
}

func resolveRedirects(urls []string) []string {
	results := make([]string, len(urls))
	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for i, rawURL := range urls {
		results[i] = validSourceURL(rawURL)
		if results[i] == "" || !googleRedirectURL(results[i]) {
			continue
		}
		wg.Add(1)
		go func(idx int, sourceURL string) {
			defer wg.Done()
			req, err := http.NewRequest("HEAD", sourceURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			resp.Body.Close()
			location, err := resp.Location()
			if err == nil {
				if resolved := validSourceURL(location.String()); resolved != "" {
					results[idx] = resolved
				}
			}
		}(i, results[i])
	}
	wg.Wait()
	return results
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
	cachedProject     string
	projectMu         sync.Mutex
	tokenMu           sync.Mutex
	cachedCreds       *oauthCreds
	cachedSessionID   = uuid.New().String()
	apiKey            string
	models            []string
	modelsConfigured  bool
	configuredProject string

	apiSem        = make(chan struct{}, 1)
	cooldownMu    sync.Mutex
	cooldownUntil time.Time
)

func loadConfig() {
	home, _ := os.UserHomeDir()
	data, err := os.ReadFile(filepath.Join(home, ".gsearch", "config.json"))
	if err != nil {
		return
	}
	var cfg map[string]any
	if json.Unmarshal(data, &cfg) != nil {
		return
	}
	if authType, _ := cfg["auth_type"].(string); authType == "api-key" {
		if key, _ := cfg["api_key"].(string); key != "" {
			apiKey = key
		}
	}
	configuredProject, _ = cfg["project"].(string)
	if m, ok := cfg["models"].([]any); ok && len(m) > 0 {
		models = nil
		for _, v := range m {
			if s, ok := v.(string); ok {
				models = append(models, s)
			}
		}
		modelsConfigured = len(models) > 0
	} else if m, _ := cfg["model"].(string); m != "" {
		models = []string{m}
		modelsConfigured = true
	}
}

func main() {
	// load config (models, api key)
	models = []string{defaultModel, fallbackModel}
	loadConfig()

	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if apiKey == "" {
		apiKey = os.Getenv("GSEARCH_API_KEY")
	}

	s := server.NewMCPServer(
		"gsearch",
		"1.2.2",
		server.WithToolCapabilities(false),
	)

	tool := mcp.NewTool("google_search",
		mcp.WithDescription("Search the web using Google Search grounding. Returns an answer with inline citations and source URLs. Use for current events, documentation, news, or any real-time web information.\n\nResponse time: 2-15s typical, up to 60s with retries. On 429 the server retries automatically with dynamic backoff (typically 2s). Avoid calling this tool in rapid succession — batch your search needs into a single, well-crafted query when possible.\n\nDo NOT use Google dork operators (site:, filetype:, inurl:, intitle:, intext:, ext:, cache:) — Prefer natural language. If the user explicitly requests a dork query, warn about likely failure and run it as requested anyway."),
		mcp.WithString("query",
			mcp.Required(),
			mcp.Description("Do NOT use Google dork operators (site:, filetype:, inurl:, intitle:, intext:, ext:, cache:) — Prefer natural language. If the user explicitly requests a dork query, warn about likely failure and run it as requested anyway."),
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
