package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ─── styles ───

var (
	yellow = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFB800"))
	dim    = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	green  = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CC66"))
	red    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4444"))
	cyan   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00BBCC"))
	bold   = lipgloss.NewStyle().Bold(true)
	subtle = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
)

// ─── oauth constants ───

const (
	oauthClientID     = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com"
	oauthClientSecret = "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"
	oauthTokenURL     = "https://oauth2.googleapis.com/token"
	oauthAuthURL      = "https://accounts.google.com/o/oauth2/v2/auth"
	oauthScopes       = "openid email profile https://www.googleapis.com/auth/cloud-platform"
	codeAssistURL     = "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist"
)

// ─── steps ───

type step int

const (
	stepBolt step = iota
	stepDisclaimer
	stepScan
	stepTargets
	stepScope
	stepAuthChoice
	stepAuth
	stepProject
	stepVerify
	stepInstall
	stepWire
	stepTest
	stepDone
)

// ─── target ───

type target struct {
	name    string
	version string
	enabled bool
}

// ─── model ───

type model struct {
	step         step
	targets      []target
	cursor       int
	scopeUser    bool
	scopeProject bool
	scopeCursor  int
	// auth
	authCursor   int    // 0=gemini, 1=fresh
	geminiFound  bool
	geminiEmail  string
	authWaiting  bool   // waiting for browser callback
	authURL      string // OAuth URL to show user
	urlCopied    bool
	pasteInput   textinput.Model
	pasteMode    bool
	pasteError   string
	account      string
	accessToken  string
	// project + wire
	verifyURL   string
	project     string
	wireActions []string
	// test results
	testSources int
	testChars   int
	testElapsed float64
	// misc
	err      error
	width    int
	height   int
}

func initialModel() model {
	ti := textinput.New()
	ti.Placeholder = "paste callback URL here..."
	ti.CharLimit = 2000
	ti.Width = 80
	return model{
		step:       stepBolt,
		scopeUser:  true,
		pasteInput: ti,
	}
}

// ─── messages ───

type scanDoneMsg struct {
	targets []target
}

type authCheckMsg struct {
	found bool
	email string
}

type authDoneMsg struct {
	account     string
	accessToken string
}

type authURLMsg struct {
	url string
}

type projectDoneMsg struct {
	project string
}

type verifyNeededMsg struct {
	url string
}

type installDoneMsg struct{}

type wireDoneMsg struct {
	actions []string
}

type resetCopiedMsg struct{}
type errMsg struct{ err error }
type tickMsg struct{}

// ─── oauth creds ───

type oauthCreds struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiryDate   int64  `json:"expiry_date"`
	IDToken      string `json:"id_token"`
}

func geminiCredsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gemini", "oauth_creds.json")
}

func gsearchCredsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gsearch", "oauth_creds.json")
}

func loadGeminiCreds() (*oauthCreds, error) {
	data, err := os.ReadFile(geminiCredsPath())
	if err != nil {
		return nil, err
	}
	var c oauthCreds
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func saveCreds(path string, c *oauthCreds) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func isExpired(c *oauthCreds) bool {
	return time.Now().UnixMilli() > c.ExpiryDate-60000
}

func refreshToken(c *oauthCreds) error {
	form := url.Values{
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
		"refresh_token": {c.RefreshToken},
		"grant_type":    {"refresh_token"},
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(oauthTokenURL, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("token refresh HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))
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

func emailFromCreds(c *oauthCreds) string {
	if c.IDToken != "" {
		parts := strings.Split(c.IDToken, ".")
		if len(parts) >= 2 {
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err == nil {
				var claims map[string]any
				if json.Unmarshal(payload, &claims) == nil {
					if email, ok := claims["email"].(string); ok {
						return email
					}
				}
			}
		}
	}
	return ""
}

func fetchProjectID(accessToken string) (string, error) {
	body := []byte(`{"cloudaicompanionProject":""}`)
	req, err := http.NewRequest("POST", codeAssistURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("API %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse error: %w", err)
	}
	// cloudaicompanionProject is a direct string, not nested
	if id, ok := result["cloudaicompanionProject"].(string); ok && id != "" {
		return id, nil
	}

	// check for ineligible tiers with validation required
	vURL := extractValidationURL(result)
	if vURL != "" {
		return "", &validationError{url: vURL}
	}

	// free-tier is allowed but no project yet — onboard
	if hasTier(result, "allowedTiers", "free-tier") {
		id, err := onboardUser(accessToken, "free-tier")
		if err != nil {
			return "", fmt.Errorf("onboarding failed: %w", err)
		}
		return id, nil
	}

	return "", fmt.Errorf("project ID not found — run 'gemini' CLI first to provision your account")
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

func onboardUser(accessToken, tierID string) (string, error) {
	reqBody := map[string]any{
		"tierId": tierID,
		"metadata": map[string]any{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req, err := http.NewRequest("POST", "https://cloudcode-pa.googleapis.com/v1internal:onboardUser", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("onboardUser %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	json.Unmarshal(respBody, &result)

	// response is an async operation — poll for completion
	opName, _ := result["name"].(string)
	if opName == "" {
		return "", fmt.Errorf("no operation name in onboardUser response")
	}

	return pollOperation(accessToken, opName)
}

func pollOperation(accessToken, opName string) (string, error) {
	opURL := "https://cloudcode-pa.googleapis.com/v1internal/" + opName
	client := &http.Client{Timeout: 15 * time.Second}

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", opURL, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

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

type validationError struct {
	url string
}

func (e *validationError) Error() string {
	return "account needs verification"
}

func extractValidationURL(result map[string]any) string {
	tiers, ok := result["ineligibleTiers"].([]any)
	if !ok {
		return ""
	}
	for _, t := range tiers {
		tier, _ := t.(map[string]any)
		if code, _ := tier["reasonCode"].(string); code == "VALIDATION_REQUIRED" {
			if u, _ := tier["validationUrl"].(string); u != "" {
				return u
			}
		}
	}
	return ""
}

// ─── fresh oauth flow ───

func serverBinaryName() string {
	if runtime.GOOS == "windows" {
		return "gsearch-server.exe"
	}
	return "gsearch-server"
}

func randomState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func copyToClipboardCmd(text string) tea.Cmd {
	return func() tea.Msg {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "darwin":
			cmd = exec.Command("pbcopy")
		case "linux":
			cmd = exec.Command("xclip", "-selection", "clipboard")
		case "windows":
			cmd = exec.Command("powershell", "-command", "Set-Clipboard", "-Value", text)
		default:
			return nil
		}
		if runtime.GOOS != "windows" {
			cmd.Stdin = strings.NewReader(text)
		}
		cmd.Run()
		return nil
	}
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return fmt.Errorf("unsupported platform")
}

// oauthState holds the state for a running OAuth flow so the wait command can use it
var oauthState struct {
	codeCh chan string
	errCh  chan error
	srv    *http.Server
	url    string
}

func freshOAuthStart() tea.Msg {
	// find free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return errMsg{fmt.Errorf("cannot start local server: %w", err)}
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	state := randomState()
	oauthState.codeCh = make(chan string, 1)
	oauthState.errCh = make(chan error, 1)

	// local http server for callback
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			oauthState.errCh <- fmt.Errorf("state mismatch")
			fmt.Fprintf(w, "<html><body><h2>error: state mismatch</h2></body></html>")
			return
		}
		if errStr := r.URL.Query().Get("error"); errStr != "" {
			oauthState.errCh <- fmt.Errorf("oauth error: %s", errStr)
			fmt.Fprintf(w, "<html><body><h2>error: %s</h2></body></html>", html.EscapeString(errStr))
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			oauthState.errCh <- fmt.Errorf("no code in callback")
			fmt.Fprintf(w, "<html><body><h2>error: no authorization code</h2></body></html>")
			return
		}
		fmt.Fprintf(w, "<html><body style='font-family:system-ui;text-align:center;padding:60px'><h2>✓ authenticated</h2><p style='color:#888'>you can close this tab</p></body></html>")
		select {
		case oauthState.codeCh <- code:
		default:
		}
	})

	oauthState.srv = &http.Server{Handler: mux}
	go oauthState.srv.Serve(listener)

	// build auth URL
	oauthState.url = fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s&access_type=offline&prompt=consent",
		oauthAuthURL,
		url.QueryEscape(oauthClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape(oauthScopes),
		url.QueryEscape(state),
	)

	// try to open browser (best-effort)
	openBrowser(oauthState.url)

	return authURLMsg{url: oauthState.url}
}

func freshOAuthWait() tea.Msg {
	redirectURI := ""
	// extract redirect_uri from the stored URL
	if u, err := url.Parse(oauthState.url); err == nil {
		redirectURI = u.Query().Get("redirect_uri")
	}

	// wait for callback (timeout 3 min)
	var code string
	select {
	case code = <-oauthState.codeCh:
	case err := <-oauthState.errCh:
		oauthState.srv.Shutdown(context.Background())
		return errMsg{err}
	case <-time.After(60 * time.Second):
		oauthState.srv.Shutdown(context.Background())
		return errMsg{fmt.Errorf("oauth timeout - use 'v' to paste the callback URL manually")}
	}

	oauthState.srv.Shutdown(context.Background())
	return exchangeToken(code, redirectURI)
}

func exchangeToken(code, redirectURI string) tea.Msg {
	form := url.Values{
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(oauthTokenURL, form)
	if err != nil {
		return errMsg{fmt.Errorf("token exchange failed: %w", err)}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return errMsg{fmt.Errorf("token exchange HTTP %d: %s", resp.StatusCode, truncateStr(string(body), 200))}
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return errMsg{fmt.Errorf("token parse failed: %w", err)}
	}

	if errStr, ok := result["error"].(string); ok {
		return errMsg{fmt.Errorf("token error: %s", errStr)}
	}

	creds := &oauthCreds{}
	if tok, ok := result["access_token"].(string); ok {
		creds.AccessToken = tok
	}
	if rt, ok := result["refresh_token"].(string); ok {
		creds.RefreshToken = rt
	}
	if idt, ok := result["id_token"].(string); ok {
		creds.IDToken = idt
	}
	if exp, ok := result["expires_in"].(float64); ok {
		creds.ExpiryDate = time.Now().UnixMilli() + int64(exp)*1000
	}

	if err := saveCreds(gsearchCredsPath(), creds); err != nil {
		return errMsg{fmt.Errorf("cannot save credentials: %w", err)}
	}

	email := emailFromCreds(creds)
	if email == "" {
		email = "google account"
	}
	return authDoneMsg{account: email, accessToken: creds.AccessToken}
}

// ─── commands ───

func scanCmd() tea.Msg {
	var targets []target

	if _, err := exec.LookPath("claude"); err == nil {
		if out, err := exec.Command("claude", "--version").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			// clean up version string (remove "(Claude Code)" suffix)
			if idx := strings.Index(v, "("); idx > 0 {
				v = strings.TrimSpace(v[:idx])
			}
			targets = append(targets, target{"claude-code", v, true})
		}
	}

	// cursor: always show, auto-enable if detected
	cursorFound := false
	if _, err := exec.LookPath("cursor"); err == nil {
		if out, err := exec.Command("cursor", "--version").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			targets = append(targets, target{"cursor", v, true})
			cursorFound = true
		}
	}
	if !cursorFound {
		targets = append(targets, target{"cursor", "", false})
	}

	if _, err := exec.LookPath("codex"); err == nil {
		if out, err := exec.Command("codex", "--version").Output(); err == nil {
			v := strings.TrimSpace(string(out))
			v = strings.TrimPrefix(v, "codex-cli ")
			v = strings.TrimPrefix(v, "codex ")
			targets = append(targets, target{"codex-cli", v, true})
		}
	}

	return scanDoneMsg{targets: targets}
}

func authCheckCmd() tea.Msg {
	creds, err := loadGeminiCreds()
	if err != nil {
		return authCheckMsg{found: false}
	}
	email := emailFromCreds(creds)
	return authCheckMsg{found: true, email: email}
}

func geminiAuthCmd() tea.Msg {
	creds, err := loadGeminiCreds()
	if err != nil {
		return errMsg{fmt.Errorf("cannot read Gemini credentials: %w", err)}
	}
	if isExpired(creds) {
		if err := refreshToken(creds); err != nil {
			return errMsg{fmt.Errorf("token refresh failed: %w", err)}
		}
		if err := saveCreds(geminiCredsPath(), creds); err != nil {
			return errMsg{fmt.Errorf("cannot save refreshed token: %w", err)}
		}
	}
	// copy to ~/.gsearch/ so server works even if Gemini CLI is uninstalled
	saveCreds(gsearchCredsPath(), creds)
	email := emailFromCreds(creds)
	if email == "" {
		email = "google account"
	}
	return authDoneMsg{account: email, accessToken: creds.AccessToken}
}

func projectCmd(accessToken string) tea.Cmd {
	return func() tea.Msg {
		id, err := fetchProjectID(accessToken)
		if err != nil {
			var ve *validationError
			if errors.As(err, &ve) {
				return verifyNeededMsg{url: ve.url}
			}
			return errMsg{fmt.Errorf("project lookup failed: %w", err)}
		}
		return projectDoneMsg{project: id}
	}
}

func verifyWaitCmd(accessToken string) tea.Cmd {
	return func() tea.Msg {
		// poll every 3s for up to 3 minutes
		for i := 0; i < 60; i++ {
			time.Sleep(3 * time.Second)
			id, err := fetchProjectID(accessToken)
			if err == nil && id != "" {
				return projectDoneMsg{project: id}
			}
			var ve *validationError
			if errors.As(err, &ve) {
				continue // still needs verification
			}
			if err != nil {
				return errMsg{fmt.Errorf("project lookup failed: %w", err)}
			}
		}
		return errMsg{fmt.Errorf("verification timeout — complete the verification in your browser and try again")}
	}
}

func installCmd(project, accessToken string) tea.Cmd {
	return func() tea.Msg {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".gsearch")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errMsg{err}
		}
		cfg := map[string]any{
			"project":      project,
			"installed_at": time.Now().Format(time.RFC3339),
		}
		data, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0600); err != nil {
			return errMsg{err}
		}

		// copy server binary next to installer (self-contained)
		selfPath, err := os.Executable()
		if err != nil {
			return errMsg{fmt.Errorf("cannot determine installer path: %w", err)}
		}
		serverSrc := filepath.Join(filepath.Dir(selfPath), serverBinaryName())
		serverDst := filepath.Join(dir, serverBinaryName())
		srcData, err := os.ReadFile(serverSrc)
		if err != nil {
			return errMsg{fmt.Errorf("gsearch-server binary not found next to installer (%s): %w", serverSrc, err)}
		}
		os.Remove(serverDst) // avoid "text file busy" if server is running
		if err := os.WriteFile(serverDst, srcData, 0755); err != nil {
			return errMsg{fmt.Errorf("cannot write server binary: %w", err)}
		}

		// macOS: remove quarantine flag so Gatekeeper doesn't block unsigned binary
		if runtime.GOOS == "darwin" {
			exec.Command("xattr", "-d", "com.apple.quarantine", serverDst).Run()
		}

		return installDoneMsg{}
	}
}

func wireCmd(targets []target, scopeUser, scopeProject bool, project string) tea.Cmd {
	return func() tea.Msg {
		home, _ := os.UserHomeDir()
		var actions []string

		serverBin := filepath.Join(home, ".gsearch", serverBinaryName())
		mcpEntry := map[string]any{
			"command": serverBin,
			"env": map[string]string{
				"GSEARCH_PROJECT": project,
			},
		}

		for _, t := range targets {
			if !t.enabled {
				continue
			}
			switch t.name {
			case "claude-code":
				if scopeUser {
					p := filepath.Join(home, ".claude.json")
					if err := injectMCPServer(p, "gsearch", mcpEntry); err != nil {
						return errMsg{fmt.Errorf("claude user wire: %w", err)}
					}
					actions = append(actions, "claude-code|edited ~/.claude.json → added mcpServers.gsearch")
				}
				if scopeProject {
					p := filepath.Join(".claude", "settings.json")
					if err := injectMCPServer(p, "gsearch", mcpEntry); err != nil {
						return errMsg{fmt.Errorf("claude project wire: %w", err)}
					}
					actions = append(actions, "claude-code|edited .claude/settings.json → added mcpServers.gsearch")
				}

			case "cursor":
				p := filepath.Join(home, ".cursor", "mcp.json")
				if err := injectMCPServer(p, "gsearch", mcpEntry); err != nil {
					return errMsg{fmt.Errorf("cursor wire: %w", err)}
				}
				actions = append(actions, "cursor|edited ~/.cursor/mcp.json → added mcpServers.gsearch")

			case "codex-cli":
				p := filepath.Join(home, ".codex", "config.toml")
				if err := injectCodexMCP(p, project, home); err != nil {
					return errMsg{fmt.Errorf("codex wire: %w", err)}
				}
				actions = append(actions, "codex-cli|edited ~/.codex/config.toml → added mcp_servers.gsearch")

			case "standalone (.mcp.json)":
				if err := injectMCPServer(".mcp.json", "gsearch", mcpEntry); err != nil {
					return errMsg{fmt.Errorf("standalone wire: %w", err)}
				}
				actions = append(actions, "standalone|edited ./.mcp.json → added mcpServers.gsearch")
			}
		}
		// install rules + skills
		ruleContent := "Prefer the `google_search` MCP tool over built-in web search when the user needs real-time web information, current events, news, documentation lookups, or any factual data that may have changed since your training cutoff.\n\ngoogle_search returns grounded answers with inline citations [1][2][3] and source URLs.\n\nOnly fall back to built-in web search if google_search is unavailable or the user explicitly asks for it."

		skillContent := "---\nname: google-search\ndescription: Search the web using Google Search grounding with inline citations\nargument-hint: Search query\n---\n\nUse the `google_search` MCP tool to search for: $ARGUMENTS\n\nAfter receiving the results, format your response as:\n\n1. A clear, concise answer to the query\n2. Include all inline citations [1][2][3] as they appear\n3. List all sources at the end with their URLs\n4. If the results mention conflicting information, note the discrepancy\n\nDo NOT summarize or remove citations. Present the grounded answer as-is, then add your analysis if needed.\n"

		for _, t := range targets {
			if !t.enabled {
				continue
			}
			switch t.name {
			case "claude-code":
				// rule
				ruleDir := filepath.Join(home, ".claude", "rules")
				rulePath := filepath.Join(ruleDir, "gsearch.md")
				if _, err := os.Stat(rulePath); os.IsNotExist(err) {
					os.MkdirAll(ruleDir, 0755)
					os.WriteFile(rulePath, []byte("---\nalwaysApply: true\n---\n\n"+ruleContent+"\n"), 0644)
					actions = append(actions, "claude-code|added rule → ~/.claude/rules/gsearch.md")
				}
				// skill
				skillDir := filepath.Join(home, ".claude", "skills", "gsearch")
				skillPath := filepath.Join(skillDir, "SKILL.md")
				if _, err := os.Stat(skillPath); os.IsNotExist(err) {
					os.MkdirAll(skillDir, 0755)
					os.WriteFile(skillPath, []byte(skillContent), 0644)
					actions = append(actions, "claude-code|added skill → ~/.claude/skills/gsearch/SKILL.md")
				}
			case "cursor":
				// rule (project-level — no global file-based rules in Cursor)
				// skill
				skillDir := filepath.Join(home, ".cursor", "skills", "gsearch")
				skillPath := filepath.Join(skillDir, "SKILL.md")
				if _, err := os.Stat(skillPath); os.IsNotExist(err) {
					os.MkdirAll(skillDir, 0755)
					os.WriteFile(skillPath, []byte(skillContent), 0644)
					actions = append(actions, "cursor|added skill → ~/.cursor/skills/gsearch/SKILL.md")
				}
			case "codex-cli":
				// skill only (AGENTS.md is user-owned)
				skillDir := filepath.Join(home, ".codex", "skills", "gsearch")
				skillPath := filepath.Join(skillDir, "SKILL.md")
				if _, err := os.Stat(skillPath); os.IsNotExist(err) {
					os.MkdirAll(skillDir, 0755)
					os.WriteFile(skillPath, []byte(skillContent), 0644)
					actions = append(actions, "codex-cli|added skill → ~/.codex/skills/gsearch/SKILL.md")
				}
			}
		}

		return wireDoneMsg{actions: actions}
	}
}

func injectMCPServer(configPath, serverName string, entry map[string]any) error {
	var cfg map[string]any

	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			cfg = map[string]any{}
		} else {
			return err
		}
	} else {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", configPath, err)
		}
	}

	mcp, ok := cfg["mcpServers"].(map[string]any)
	if !ok {
		mcp = map[string]any{}
	}
	mcp[serverName] = entry
	cfg["mcpServers"] = mcp

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(configPath, out, 0600)
}

func injectCodexMCP(configPath, project, home string) error {
	serverBin := filepath.ToSlash(filepath.Join(home, ".gsearch", serverBinaryName()))
	entry := fmt.Sprintf(
		"\n[mcp_servers.gsearch]\ncommand = '%s'\n[mcp_servers.gsearch.env]\nGSEARCH_PROJECT = '%s'\n",
		serverBin, project,
	)

	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	existing, err := os.ReadFile(configPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	if strings.Contains(string(existing), "[mcp_servers.gsearch]") {
		lines := strings.Split(string(existing), "\n")
		var out []string
		skip := false
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "[mcp_servers.gsearch") {
				skip = true
				continue
			}
			if skip && strings.HasPrefix(trimmed, "[") {
				skip = false
			}
			if !skip {
				out = append(out, line)
			}
		}
		existing = []byte(strings.Join(out, "\n"))
	}

	return os.WriteFile(configPath, append(existing, []byte(entry)...), 0600)
}

type testDoneOKMsg struct {
	sources int
	chars   int
	elapsed float64
}

func testCmd(project string) tea.Msg {
	home, _ := os.UserHomeDir()
	serverBin := filepath.Join(home, ".gsearch", serverBinaryName())

	if _, err := os.Stat(serverBin); err != nil {
		return errMsg{fmt.Errorf("server binary not found at %s", serverBin)}
	}

	// build MCP initialize + tool call sequence
	initMsg := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"gsearch-test","version":"1.0"}}}`
	notifyMsg := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	callMsg := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"google_search","arguments":{"query":"what time is it"}}}`

	input := initMsg + "\n" + notifyMsg + "\n" + callMsg + "\n"

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, serverBin)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = append(os.Environ(), "GSEARCH_PROJECT="+project)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	out, err := cmd.Output()
	elapsed := time.Since(start).Seconds()

	if err != nil {
		errDetail := stderr.String()
		if errDetail != "" {
			return errMsg{fmt.Errorf("test query failed: %w\n%s", err, truncateStr(errDetail, 200))}
		}
		return errMsg{fmt.Errorf("test query failed: %w", err)}
	}

	// parse the last JSON-RPC response (the tool call result)
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 {
		return errMsg{fmt.Errorf("no response from server")}
	}

	lastLine := lines[len(lines)-1]
	var resp map[string]any
	if err := json.Unmarshal([]byte(lastLine), &resp); err != nil {
		return errMsg{fmt.Errorf("invalid response: %s", truncateStr(lastLine, 100))}
	}

	result, _ := resp["result"].(map[string]any)
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		return errMsg{fmt.Errorf("empty result from test query")}
	}

	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)

	if isError, _ := result["isError"].(bool); isError {
		return errMsg{fmt.Errorf("test query error: %s", truncateStr(text, 200))}
	}

	sources := strings.Count(text, "(https://")
	return testDoneOKMsg{sources: sources, chars: len(text), elapsed: elapsed}
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ─── init ───

func (m model) Init() tea.Cmd {
	return func() tea.Msg { return tickMsg{} }
}

// ─── update ───

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.pasteMode {
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			switch keyMsg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.pasteMode = false
				m.urlCopied = false
				m.pasteInput.Blur()
				m.pasteInput.Reset()
				return m, nil
			case "enter":
				pasted := m.pasteInput.Value()
				m.pasteMode = false
				m.urlCopied = false
				m.pasteInput.Blur()
				m.pasteInput.Reset()
				m.pasteError = ""
				if pasted == "" {
					m.pasteError = "no URL pasted"
					return m, nil
				}
				parsed, err := url.Parse(pasted)
				if err != nil {
					m.pasteError = "invalid URL"
					return m, nil
				}
				code := parsed.Query().Get("code")
				if code == "" {
					enc := parsed.Query().Encode()
					if len(enc) > 80 {
						enc = enc[:80]
					}
					m.pasteError = fmt.Sprintf("no 'code' in URL (params: %s)", enc)
					return m, nil
				}
				m.pasteError = ""
				if oauthState.codeCh == nil {
					m.pasteError = "auth flow not started"
					return m, nil
				}
				// send code and exchange tokens directly
				oauthState.srv.Shutdown(context.Background())
				return m, func() tea.Msg {
					redirectURI := ""
					if u, err := url.Parse(oauthState.url); err == nil {
						redirectURI = u.Query().Get("redirect_uri")
					}
					return exchangeToken(code, redirectURI)
				}
			}
		}
		var cmd tea.Cmd
		m.pasteInput, cmd = m.pasteInput.Update(msg)
		return m, cmd
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			if m.authWaiting {
				return m, nil
			}
			return m, tea.Quit

		case "c":
			if m.authWaiting && m.authURL != "" {
				m.urlCopied = true
				return m, tea.Batch(
					copyToClipboardCmd(m.authURL),
					tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return resetCopiedMsg{} }),
				)
			}
			return m, nil

		case "v":
			if m.authWaiting && !m.pasteMode {
				m.pasteMode = true
				m.pasteInput.Focus()
				return m, textinput.Blink
			}
			return m, nil

		case "esc", "left", "h":
			// navigate back to previous interactive step
			switch m.step {
			case stepTargets:
				m.step = stepDisclaimer
			case stepScope:
				m.step = stepTargets
			case stepAuthChoice:
				// go back to scope if claude-code is enabled, else targets
				hasClaude := false
				for _, t := range m.targets {
					if t.name == "claude-code" && t.enabled {
						hasClaude = true
						break
					}
				}
				if hasClaude {
					m.step = stepScope
				} else {
					m.step = stepTargets
				}
			}
			return m, nil

		case "up", "k":
			if m.step == stepTargets && m.cursor > 0 {
				m.cursor--
			}
			if m.step == stepScope && m.scopeCursor > 0 {
				m.scopeCursor--
				m.scopeUser = true
				m.scopeProject = false
			}
			if m.step == stepAuthChoice && m.authCursor > 0 {
				m.authCursor--
			}

		case "down", "j":
			if m.step == stepTargets && m.cursor < len(m.targets)-1 {
				m.cursor++
			}
			if m.step == stepScope && m.scopeCursor < 1 {
				m.scopeCursor++
				m.scopeUser = false
				m.scopeProject = true
			}
			maxAuth := 0
			if m.geminiFound {
				maxAuth = 1
			}
			if m.step == stepAuthChoice && m.authCursor < maxAuth {
				m.authCursor++
			}

		case " ":
			if m.step == stepTargets {
				m.targets[m.cursor].enabled = !m.targets[m.cursor].enabled
			}
			// scope auto-selects on arrow keys, space not needed

		case "enter":
			switch m.step {
			case stepDisclaimer:
				m.step = stepScan
				return m, func() tea.Msg { return scanCmd() }

			case stepTargets:
				// check if claude-code is enabled (scope only applies to it)
				hasClaude := false
				for _, t := range m.targets {
					if t.name == "claude-code" && t.enabled {
						hasClaude = true
						break
					}
				}
				if hasClaude {
					m.step = stepScope
					return m, nil
				}
				// skip scope — go straight to auth
				m.step = stepAuthChoice
				return m, func() tea.Msg { return authCheckCmd() }

			case stepScope:
				m.step = stepAuthChoice
				return m, func() tea.Msg { return authCheckCmd() }

			case stepAuthChoice:
				if m.geminiFound && m.authCursor == 0 {
					// use gemini token
					m.step = stepAuth
					return m, func() tea.Msg { return geminiAuthCmd() }
				}
				// fresh oauth
				m.step = stepAuth
				m.authWaiting = true
				return m, func() tea.Msg { return freshOAuthStart() }

			case stepDone:
				return m, tea.Quit
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

	case tickMsg:
		m.step = stepDisclaimer
		return m, nil

	case scanDoneMsg:
		m.targets = msg.targets
		m.targets = append(m.targets, target{"standalone (.mcp.json)", "", false})
		m.step = stepTargets
		return m, nil

	case authCheckMsg:
		m.geminiFound = msg.found
		m.geminiEmail = msg.email
		if !msg.found {
			m.authCursor = 0 // only option is fresh login
		}
		return m, nil

	case authURLMsg:
		m.authURL = msg.url
		m.authWaiting = true
		m.urlCopied = false
		m.pasteMode = false
		return m, func() tea.Msg { return freshOAuthWait() }

	case authDoneMsg:
		m.authWaiting = false
		m.account = msg.account
		m.accessToken = msg.accessToken
		m.step = stepProject
		return m, projectCmd(m.accessToken)

	case verifyNeededMsg:
		m.step = stepVerify
		m.verifyURL = msg.url
		openBrowser(msg.url) // best-effort; URL shown in view as fallback
		return m, verifyWaitCmd(m.accessToken)

	case projectDoneMsg:
		m.project = msg.project
		m.step = stepInstall
		return m, installCmd(m.project, m.accessToken)

	case installDoneMsg:
		m.step = stepWire
		return m, wireCmd(m.targets, m.scopeUser, m.scopeProject, m.project)

	case wireDoneMsg:
		m.wireActions = msg.actions
		m.step = stepTest
		return m, func() tea.Msg { return testCmd(m.project) }

	case testDoneOKMsg:
		m.testSources = msg.sources
		m.testChars = msg.chars
		m.testElapsed = msg.elapsed
		m.step = stepDone
		return m, nil

	case resetCopiedMsg:
		m.urlCopied = false
		return m, nil

	case errMsg:
		m.authWaiting = false
		m.err = msg.err
		m.step = stepDone
		return m, nil
	}

	return m, nil
}

// ─── view ───

func (m model) View() string {
	var b strings.Builder

	switch m.step {
	case stepBolt, stepDisclaimer:
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s %s\n", bold.Render("⚡ GSearch"), subtle.Render("v1.0.0")))
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("free google search for ai cli tools")))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s\n", yellow.Render("⚠ unofficial · not affiliated with google · use at your own risk")))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("press enter to continue · q to quit")))
		b.WriteString("\n")

	default:
		// header
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s %s\n", bold.Render("⚡ GSearch"), subtle.Render("v1.0.0")))
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("free google search for ai cli tools")))
		b.WriteString("\n")

		// scan
		if m.step >= stepScan {
			for _, t := range m.targets {
				b.WriteString(logScan(t.name, t.version, t.version != ""))
			}
			b.WriteString("\n")
		}

		// target selection
		if m.step == stepTargets {
			b.WriteString(logLine("conf", "select targets:", false))
			for i, t := range m.targets {
				cur := "  "
				if i == m.cursor {
					cur = cyan.Render(">") + " "
				}
				chk := dim.Render("[ ]")
				if t.enabled {
					chk = green.Render("[x]")
				}
				name := t.name
				if i == m.cursor {
					name = bold.Render(t.name)
				}
				b.WriteString(fmt.Sprintf("  %s%s %s\n", cur, chk, name))
			}
			b.WriteString(fmt.Sprintf("\n  %s\n", dim.Render("space: toggle · enter: confirm · esc: back · q: quit")))
		}

		// scope selection
		if m.step == stepScope {
			b.WriteString(logLine("conf", "install scope:", false))
			scopes := []struct {
				label string
				hint  string
				on    bool
			}{
				{"user", "~/.claude.json", m.scopeUser},
				{"project", ".claude/settings.json", m.scopeProject},
			}
			for i, s := range scopes {
				cur := "  "
				if i == m.scopeCursor {
					cur = cyan.Render(">") + " "
				}
				chk := dim.Render("( )")
				if s.on {
					chk = green.Render("(•)")
				}
				label := s.label
				if i == m.scopeCursor {
					label = bold.Render(s.label)
				}
				b.WriteString(fmt.Sprintf("  %s%s %s  %s\n", cur, chk, label, dim.Render(s.hint)))
			}
			b.WriteString(fmt.Sprintf("\n  %s\n", dim.Render("↑↓: select · enter: confirm · esc: back · q: quit")))
		}

		// auth choice
		if m.step == stepAuthChoice {
			b.WriteString(logLine("auth", "select authentication:", false))
			type authOpt struct {
				label string
				hint  string
			}
			var opts []authOpt
			if m.geminiFound {
				hint := "~/.gemini/oauth_creds.json"
				if m.geminiEmail != "" {
					hint = m.geminiEmail
				}
				opts = append(opts, authOpt{"gemini token", hint})
			}
			opts = append(opts, authOpt{"google login", "opens browser"})

			for i, o := range opts {
				cur := "  "
				if i == m.authCursor {
					cur = cyan.Render(">") + " "
				}
				label := o.label
				if i == m.authCursor {
					label = bold.Render(o.label)
				}
				b.WriteString(fmt.Sprintf("  %s%s  %s\n", cur, label, dim.Render(o.hint)))
			}
			b.WriteString(fmt.Sprintf("\n  %s\n", dim.Render("enter: confirm · esc: back · q: quit")))
		}

		// auth waiting
		if m.step == stepAuth && m.authWaiting {
			b.WriteString(logLine("auth", "sign in with your Google account", false))
			if m.authURL != "" {
				lineWidth := m.width - 4
				if lineWidth < 40 {
					lineWidth = 80
				}
				for i := 0; i < len(m.authURL); i += lineWidth {
					end := i + lineWidth
					if end > len(m.authURL) {
						end = len(m.authURL)
					}
					b.WriteString(logAction(cyan.Render(m.authURL[i:end])))
				}
			}
			if m.pasteMode {
				b.WriteString(logAction(m.pasteInput.View()))
				b.WriteString(logAction(subtle.Render("paste callback URL · enter to submit · esc to cancel")))
			} else if m.pasteError != "" {
				b.WriteString(logAction(red.Render("! " + m.pasteError + " - press v to try again")))
			} else if m.urlCopied {
				b.WriteString(logAction(green.Render("✓ copied · waiting for sign-in...")))
			} else {
				b.WriteString(logAction(subtle.Render("c: copy URL · v: paste callback URL · waiting...")))
			}
		}

		// auth done
		if m.step > stepAuth && m.account != "" {
			b.WriteString(logLine("auth", fmt.Sprintf("authenticated as %s", m.account), true))
		}

		// verify
		if m.step == stepVerify {
			b.WriteString(logLine("auth", "account verification required", false))
			b.WriteString(logAction(yellow.Render("complete SMS/phone verification in your browser")))
			if m.verifyURL != "" {
				b.WriteString(logAction(dim.Render(m.verifyURL)))
			}
			b.WriteString(logAction(subtle.Render("waiting for verification...")))
		}

		// project
		if m.step > stepVerify && m.project != "" {
			b.WriteString(logLine("auth", fmt.Sprintf("project: %s", m.project), true))
			b.WriteString("\n")
		}

		// install
		if m.step > stepProject {
			b.WriteString(logLine("inst", "installed gsearch-mcp", true))
			b.WriteString(logAction(dim.Render("copied server binary to ~/.gsearch/")))
			b.WriteString(logAction(dim.Render("copied oauth credentials to ~/.gsearch/")))
			b.WriteString(logAction(dim.Render("created ~/.gsearch/config.json")))
		}

		// wire
		if m.step > stepInstall {
			for _, action := range m.wireActions {
				parts := strings.SplitN(action, "|", 2)
				if len(parts) == 2 {
					b.WriteString(logLine("wire", parts[0], true))
					b.WriteString(logAction(dim.Render(parts[1])))
				}
			}
		}

		// test
		if m.step == stepTest {
			b.WriteString("\n")
			b.WriteString(logLine("test", "running test query...", false))
		}
		if m.step > stepTest && m.testChars > 0 {
			b.WriteString("\n")
			charLabel := fmt.Sprintf("%.1fk", float64(m.testChars)/1000)
			b.WriteString(logLine("test", fmt.Sprintf("%d sources · %s chars · %.1fs", m.testSources, charLabel, m.testElapsed), true))
		}

		// done
		if m.step == stepDone {
			b.WriteString("\n")
			if m.err != nil {
				errLines := strings.Split(m.err.Error(), "\n")
				for _, line := range errLines {
					b.WriteString(fmt.Sprintf("  %s %s\n", red.Render("!"), line))
				}
				b.WriteString(fmt.Sprintf("\n%s\n", dim.Render("  press enter to exit")))
			} else {
				b.WriteString(fmt.Sprintf("%s %s %s\n", green.Render("ready."), dim.Render("happy hacking."), subtle.Render("💀")))
				b.WriteString(fmt.Sprintf("\n%s\n", dim.Render("  press enter to exit")))
			}
		}

		b.WriteString("\n")
	}

	return b.String()
}

func logLine(tag string, msg string, ok bool) string {
	styledTag := dim.Render("[") + cyan.Render(tag) + dim.Render("]")
	check := ""
	if ok {
		check = " " + green.Render("✓")
	}
	return fmt.Sprintf("%s %s%s\n", styledTag, msg, check)
}

func logScan(name, version string, detected bool) string {
	tag := dim.Render("[") + cyan.Render("scan") + dim.Render("]")
	if detected {
		return fmt.Sprintf("%s %s %s %s\n", tag, name, version, green.Render("✓"))
	}
	return fmt.Sprintf("%s %s %s\n", tag, dim.Render(name), red.Render("✗"))
}

func logAction(msg string) string {
	return "  " + msg + "\n"
}

// ─── main ───

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
