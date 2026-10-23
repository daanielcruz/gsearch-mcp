package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// ─── oauth + antigravity constants ───

const (
	oauthClientID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	oauthClientSecret = "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"
	oauthAuthURL      = "https://accounts.google.com/o/oauth2/auth"
	oauthTokenURL     = "https://oauth2.googleapis.com/token"
	oauthUserinfoURL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	oauthScopes       = "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/aicode https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
	credsProvider     = "antigravity"
)

func codeAssistBaseURL() string {
	if os.Getenv("GSEARCH_ANTIGRAVITY_HOST") == "prod" {
		return "https://cloudcode-pa.googleapis.com/v1internal"
	}
	return "https://daily-cloudcode-pa.googleapis.com/v1internal"
}

func antigravityUserAgent() string {
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	return fmt.Sprintf("antigravity/cli/1.4.6 (aidev_client; os_type=%s; arch=%s; cl=1005129088; auth_method=consumer)", runtime.GOOS, arch)
}

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
	authCursor  int    // 0=Login Google (Antigravity), 1=API key
	authWaiting bool   // waiting for browser callback
	authURL     string // OAuth URL to show user
	urlCopied   bool
	pasteInput  textinput.Model
	pasteMode   bool
	pasteError  string
	account     string
	accessToken string
	useAPIKey   bool
	apiKeyInput textinput.Model
	apiKeyMode  bool
	// project + wire
	verifyURL        string
	project          string
	projectInput     textinput.Model
	projectInputMode bool
	projectError     string
	projectTier      string
	installed        bool
	wireActions      []string
	// test results
	testSources int
	testChars   int
	testElapsed float64
	testText    string
	// misc
	err    error
	width  int
	height int
}

func initialModel() model {
	ti := textinput.New()
	ti.Placeholder = "paste callback URL here..."
	ti.CharLimit = 2000
	ti.Width = 80
	projectInput := textinput.New()
	projectInput.Placeholder = "Project ID do Google Cloud"
	projectInput.Width = 60
	return model{
		step:         stepBolt,
		scopeUser:    true,
		pasteInput:   ti,
		projectInput: projectInput,
	}
}

// ─── messages ───

type scanDoneMsg struct {
	targets []target
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

type projectNeededMsg struct {
	tierID string
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
	Provider     string `json:"provider,omitempty"`
}

func gsearchCredsPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".gsearch", "oauth_creds.json")
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

// ─── code assist project lookup ───

func projectFromEnv() string {
	for _, key := range []string{"GSEARCH_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID"} {
		if project := os.Getenv(key); project != "" {
			return project
		}
	}
	return ""
}

func fetchProjectID(accessToken string) (string, error) {
	if project := projectFromEnv(); project != "" {
		return project, nil
	}
	return loadCodeAssistProject(accessToken)
}

func loadCodeAssistProject(accessToken string) (string, error) {
	loadReq, _ := json.Marshal(map[string]any{
		"metadata": map[string]any{"ideType": "ANTIGRAVITY"},
	})
	req, err := http.NewRequest("POST", codeAssistBaseURL()+":loadCodeAssist", bytes.NewReader(loadReq))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", antigravityUserAgent())

	client := &http.Client{Timeout: 20 * time.Second}
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

	// find default tier from allowedTiers
	tier := getDefaultTier(result)
	if tier == nil {
		return "", fmt.Errorf("nenhum tier elegível; defina GSEARCH_PROJECT")
	}

	tierID, _ := tier["id"].(string)
	needsProject, _ := tier["userDefinedCloudaicompanionProject"].(bool)
	if needsProject {
		return "", &projectRequiredError{tierID: tierID}
	}

	id, err := onboardUser(accessToken, tierID)
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
	if len(tiers) > 0 {
		tier, _ := tiers[0].(map[string]any)
		return tier
	}
	return nil
}

func onboardUser(accessToken, tierID string) (string, error) {
	bodyBytes, _ := json.Marshal(map[string]any{
		"tierId":   tierID,
		"metadata": map[string]any{"ideType": "ANTIGRAVITY"},
	})

	req, err := http.NewRequest("POST", codeAssistBaseURL()+":onboardUser", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", antigravityUserAgent())

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
		return "", fmt.Errorf("onboardUser %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]any
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse onboardUser response: %w", err)
	}

	if id, done, err := operationProjectID(result); done || err != nil {
		return id, err
	}

	opName, _ := result["name"].(string)
	if opName == "" {
		return "", fmt.Errorf("no operation name in onboardUser response")
	}

	return pollOperation(accessToken, opName)
}

func pollOperation(accessToken, opName string) (string, error) {
	opURL := codeAssistBaseURL() + "/" + opName
	client := &http.Client{Timeout: 15 * time.Second}

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest("GET", opURL, nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", antigravityUserAgent())

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
			return "", fmt.Errorf("operation HTTP %d: %s", resp.StatusCode, string(body))
		}

		var result map[string]any
		if err := json.Unmarshal(body, &result); err != nil {
			return "", fmt.Errorf("parse operation response: %w", err)
		}
		if id, done, err := operationProjectID(result); done || err != nil {
			return id, err
		}

		time.Sleep(2 * time.Second)
	}

	return "", fmt.Errorf("tempo limite do onboarding esgotado")
}

func operationProjectID(result map[string]any) (string, bool, error) {
	if opErr, ok := result["error"].(map[string]any); ok {
		return "", false, fmt.Errorf("operation error (code %v): %v", opErr["code"], opErr["message"])
	}
	if done, _ := result["done"].(bool); !done {
		return "", false, nil
	}
	response, _ := result["response"].(map[string]any)
	project, _ := response["cloudaicompanionProject"].(map[string]any)
	if id, _ := project["id"].(string); id != "" {
		return id, true, nil
	}
	return "", true, fmt.Errorf("onboarding completed but no project ID in response")
}

type projectRequiredError struct {
	tierID string
}

func (e *projectRequiredError) Error() string {
	return fmt.Sprintf("esta conta exige o env GSEARCH_PROJECT ou GOOGLE_CLOUD_PROJECT (tier: %s)", e.tierID)
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

// ─── antigravity oauth flow ───

func serverBinaryName() string {
	if runtime.GOOS == "windows" {
		return "gsearch-server.exe"
	}
	return "gsearch-server"
}

func randomState() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomVerifier() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func buildAuthURL(redirectURI, state, challenge string) string {
	q := url.Values{
		"client_id":             {oauthClientID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {oauthScopes},
		"state":                 {state},
		"access_type":           {"offline"},
		"prompt":                {"consent"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return oauthAuthURL + "?" + q.Encode()
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
	codeCh      chan string
	errCh       chan error
	srv         *http.Server
	url         string
	state       string
	verifier    string
	redirectURI string
}

func listenLoopback() (net.Listener, error) {
	for port := 54565; port <= 54628; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return l, nil
		}
	}
	return net.Listen("tcp", "127.0.0.1:0")
}

func startCallbackServer() error {
	listener, err := listenLoopback()
	if err != nil {
		return fmt.Errorf("cannot start local server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	state := randomState()
	verifier := randomVerifier()
	oauthState.codeCh = make(chan string, 1)
	oauthState.errCh = make(chan error, 1)
	oauthState.state = state
	oauthState.verifier = verifier
	oauthState.redirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("state") != oauthState.state {
			http.Error(w, "state mismatch", http.StatusUnauthorized)
			return
		}
		if errStr := q.Get("error"); errStr != "" {
			oauthState.errCh <- fmt.Errorf("oauth error: %s", errStr)
			http.Error(w, errStr, http.StatusBadRequest)
			return
		}
		code := q.Get("code")
		if code == "" {
			oauthState.errCh <- fmt.Errorf("no code in callback")
			http.Error(w, "no authorization code", http.StatusBadRequest)
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

	oauthState.url = buildAuthURL(oauthState.redirectURI, state, pkceChallenge(verifier))
	return nil
}

func freshOAuthStart() tea.Msg {
	if err := startCallbackServer(); err != nil {
		return errMsg{err}
	}

	// try to open browser (best-effort)
	openBrowser(oauthState.url)

	return authURLMsg{url: oauthState.url}
}

func freshOAuthWait() tea.Msg {
	// wait for callback (timeout)
	var code string
	select {
	case code = <-oauthState.codeCh:
	case err := <-oauthState.errCh:
		oauthState.srv.Shutdown(context.Background())
		return errMsg{err}
	case <-time.After(5 * time.Minute):
		oauthState.srv.Shutdown(context.Background())
		return errMsg{fmt.Errorf("Tempo do login esgotado. Inicie o instalador novamente para gerar uma nova autorização.")}
	}

	oauthState.srv.Shutdown(context.Background())
	return exchangeToken(code, oauthState.redirectURI, oauthState.verifier)
}

func exchangeToken(code, redirectURI, verifier string) tea.Msg {
	form := url.Values{
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
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

	creds := &oauthCreds{Provider: credsProvider}
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

	if creds.RefreshToken == "" {
		return errMsg{fmt.Errorf("resposta do Google sem refresh_token; não é possível renovar o acesso")}
	}

	if err := saveCreds(gsearchCredsPath(), creds); err != nil {
		return errMsg{fmt.Errorf("cannot save credentials: %w", err)}
	}

	email := emailFromCreds(creds)
	if email == "" {
		email = fetchUserinfoEmail(creds.AccessToken)
	}
	if email == "" {
		email = "Conta Google"
	}
	return authDoneMsg{account: email, accessToken: creds.AccessToken}
}

func fetchUserinfoEmail(accessToken string) string {
	req, err := http.NewRequest("GET", oauthUserinfoURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	var result map[string]any
	if json.Unmarshal(body, &result) != nil {
		return ""
	}
	email, _ := result["email"].(string)
	return email
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

	otherside := target{name: "otherside"}
	if _, err := exec.LookPath("otherside"); err == nil {
		if out, err := exec.Command("otherside", "--version").Output(); err == nil {
			otherside.version = strings.TrimPrefix(strings.TrimSpace(string(out)), "otherside ")
			otherside.enabled = true
		}
	}
	targets = append(targets, otherside)

	return scanDoneMsg{targets: targets}
}

func projectCmd(accessToken string) tea.Cmd {
	return projectLookupCmd(accessToken, "")
}

func projectLookupCmd(accessToken, projectID string) tea.Cmd {
	return func() tea.Msg {
		// manual project is a config value only; no onboarding call is made
		if projectID != "" {
			return projectDoneMsg{project: projectID}
		}
		id, err := fetchProjectID(accessToken)
		if err != nil {
			var pe *projectRequiredError
			if errors.As(err, &pe) {
				return projectNeededMsg{tierID: pe.tierID}
			}
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
		for i := 0; i < 60; i++ {
			time.Sleep(3 * time.Second)
			msg := projectLookupCmd(accessToken, "")()
			if _, ok := msg.(verifyNeededMsg); ok {
				continue
			}
			return msg
		}
		return errMsg{err: fmt.Errorf("Tempo de verificação esgotado. Conclua a verificação e tente novamente.")}
	}
}

func installerConfig(m model) map[string]any {
	if m.useAPIKey {
		return map[string]any{
			"auth_type":    "api-key",
			"api_key":      m.accessToken,
			"installed_at": time.Now().Format(time.RFC3339),
		}
	}
	return map[string]any{
		"auth_type":    "oauth",
		"project":      m.project,
		"installed_at": time.Now().Format(time.RFC3339),
	}
}

func installCmd(m model) tea.Cmd {
	return func() tea.Msg {
		home, _ := os.UserHomeDir()
		dir := filepath.Join(home, ".gsearch")
		if err := os.MkdirAll(dir, 0755); err != nil {
			return errMsg{err}
		}
		cfg := installerConfig(m)
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

func resolveOthersideMCPPath(home, goos string) string {
	root := os.Getenv("OTHERSIDE_CONFIG_DIR")
	if root == "" {
		if goos == "windows" {
			appData := os.Getenv("APPDATA")
			if appData == "" {
				appData = filepath.Join(home, "AppData", "Roaming")
			}
			root = filepath.Join(appData, "Otherside")
		} else {
			root = filepath.Join(home, ".otherside")
		}
	}
	return filepath.Join(root, ".mcp.json")
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
					p := ".mcp.json"
					if err := injectMCPServer(p, "gsearch", mcpEntry); err != nil {
						return errMsg{fmt.Errorf("claude project wire: %w", err)}
					}
					actions = append(actions, "claude-code|edited .mcp.json → added mcpServers.gsearch")
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

			case "otherside":
				p := resolveOthersideMCPPath(home, runtime.GOOS)
				if err := injectMCPServer(p, "gsearch", mcpEntry); err != nil {
					return errMsg{fmt.Errorf("Otherside: %w", err)}
				}
				actions = append(actions, "otherside|configurado "+p)

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
		if cfg == nil {
			cfg = map[string]any{}
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
	text    string
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
	callMsg := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"google_search","arguments":{"query":"latest news today"}}}`

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
	return testDoneOKMsg{sources: sources, chars: len(text), elapsed: elapsed, text: text}
}

func wrapLine(s string, width int) []string {
	if width <= 0 || len(s) <= width {
		return []string{s}
	}
	var out []string
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{s}
	}
	cur := ""
	for _, w := range words {
		if cur == "" {
			cur = w
			continue
		}
		if len(cur)+1+len(w) <= width {
			cur += " " + w
		} else {
			out = append(out, cur)
			cur = w
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
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
	if m.step == stepProject && m.projectInputMode {
		if keyMsg, ok := msg.(tea.KeyMsg); ok {
			if keyMsg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			switch keyMsg.String() {
			case "esc":
				m.projectInputMode = false
				m.projectInput.Blur()
				m.projectError = ""
				m.step = stepAuthChoice
				return m, nil
			case "enter":
				projectID := strings.TrimSpace(m.projectInput.Value())
				if projectID == "" || strings.Trim(projectID, "0123456789") == "" {
					m.projectError = "Informe o Project ID, não o número do projeto."
					return m, nil
				}
				m.projectInput.SetValue(projectID)
				m.projectError = ""
				return m, projectLookupCmd(m.accessToken, projectID)
			}
		}
		if _, ok := msg.(tea.KeyMsg); ok {
			var cmd tea.Cmd
			m.projectInput, cmd = m.projectInput.Update(msg)
			return m, cmd
		}
	}
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
				m.pasteError = ""
				if pasted == "" {
					m.pasteError = "no URL pasted"
					return m, nil
				}
				if oauthState.codeCh == nil {
					m.pasteError = "auth flow not started"
					return m, nil
				}
				parsed, err := url.Parse(pasted)
				if err != nil {
					m.pasteError = "invalid URL"
					return m, nil
				}
				if parsed.Query().Get("state") != oauthState.state {
					m.pasteError = "state divergente no callback"
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
				m.pasteMode = false
				m.urlCopied = false
				m.pasteInput.Blur()
				m.pasteInput.Reset()
				select {
				case oauthState.codeCh <- code:
				default:
				}
				return m, nil
			}
		}
		var cmd tea.Cmd
		m.pasteInput, cmd = m.pasteInput.Update(msg)
		return m, cmd
	}

	// API key input mode
	if m.apiKeyMode {
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "ctrl+c":
				return m, tea.Quit
			case "esc":
				m.apiKeyMode = false
				m.step = stepAuthChoice
				return m, nil
			case "enter":
				key := strings.TrimSpace(m.apiKeyInput.Value())
				if key == "" {
					return m, nil
				}
				m.apiKeyMode = false
				m.useAPIKey = true
				m.accessToken = key
				m.account = "API key"
				m.step = stepInstall
				return m, installCmd(m)
			}
			var cmd tea.Cmd
			m.apiKeyInput, cmd = m.apiKeyInput.Update(msg)
			return m, cmd
		}
		var cmd tea.Cmd
		m.apiKeyInput, cmd = m.apiKeyInput.Update(msg)
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
			if m.step == stepAuthChoice && m.authCursor < 1 {
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
				m.step = stepAuthChoice
				return m, nil

			case stepScope:
				m.step = stepAuthChoice
				return m, nil

			case stepAuthChoice:
				switch m.authCursor {
				case 0:
					// Login Google (Antigravity)
					m.step = stepAuth
					m.authWaiting = true
					return m, func() tea.Msg { return freshOAuthStart() }
				case 1:
					// API key
					m.step = stepAuth
					m.apiKeyMode = true
					m.apiKeyInput = textinput.New()
					m.apiKeyInput.Placeholder = "AIza..."
					m.apiKeyInput.Focus()
					m.apiKeyInput.CharLimit = 100
					return m, m.apiKeyInput.Focus()
				}

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
		m.projectInputMode = false
		m.step = stepProject
		return m, projectCmd(m.accessToken)

	case projectNeededMsg:
		m.step = stepProject
		m.projectInputMode = true
		m.projectTier = msg.tierID
		m.projectError = ""
		return m, m.projectInput.Focus()

	case verifyNeededMsg:
		m.step = stepVerify
		m.verifyURL = msg.url
		openBrowser(msg.url) // best-effort; URL shown in view as fallback
		return m, verifyWaitCmd(m.accessToken)

	case projectDoneMsg:
		m.project = msg.project
		m.projectInputMode = false
		m.projectInput.Blur()
		m.step = stepInstall
		return m, installCmd(m)

	case installDoneMsg:
		m.installed = true
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
		m.testText = msg.text
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

	if m.step == stepProject && m.projectInputMode {
		var cmd tea.Cmd
		m.projectInput, cmd = m.projectInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

// ─── view ───

func (m model) View() string {
	var b strings.Builder

	switch m.step {
	case stepBolt, stepDisclaimer:
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s %s\n", bold.Render("⚡ GSearch"), subtle.Render("v1.2.1")))
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("Pesquisa Google para ferramentas de IA")))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s\n", yellow.Render("⚠ unofficial · not affiliated with google · use at your own risk")))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("press enter to continue · q to quit")))
		b.WriteString("\n")

	default:
		// header
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s %s\n", bold.Render("⚡ GSearch"), subtle.Render("v1.2.1")))
		b.WriteString(fmt.Sprintf("%s\n", dim.Render("Pesquisa Google para ferramentas de IA")))
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
				{"project", ".mcp.json", m.scopeProject},
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
			b.WriteString(logLine("auth", "escolha a autenticação:", false))
			type authOpt struct {
				label string
				hint  string
			}
			opts := []authOpt{
				{"Login Google (Antigravity)", "OAuth pelo navegador com sua conta Google"},
				{"API key", "cole uma API key do Google AI Studio"},
			}

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

		// api key input
		if m.step == stepAuth && m.apiKeyMode {
			b.WriteString(logLine("auth", "enter your Gemini API key:", false))
			b.WriteString(logAction(dim.Render("get one at https://aistudio.google.com/apikey")))
			b.WriteString(logAction(m.apiKeyInput.View()))
			b.WriteString(fmt.Sprintf("\n  %s\n", dim.Render("enter: confirm · esc: back")))
		}

		// auth waiting
		if m.step == stepAuth && m.authWaiting {
			b.WriteString(logLine("auth", "faça login com sua conta Google (Antigravity)", false))
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
			b.WriteString(logLine("auth", "verificação de conta necessária", false))
			b.WriteString(logAction(yellow.Render("conclua a verificação por SMS/telefone no navegador")))
			if m.verifyURL != "" {
				b.WriteString(logAction(dim.Render(m.verifyURL)))
			}
			b.WriteString(logAction(subtle.Render("aguardando verificação...")))
		}

		if m.step == stepProject && m.projectInputMode {
			b.WriteString(logLine("auth", "Esta conta exige um Project ID do Google Cloud.", false))
			b.WriteString(logAction("O valor informado fica salvo apenas em ~/.gsearch/config.json."))
			b.WriteString(logAction("Use o Project ID existente da conta, não o número do projeto."))
			b.WriteString(logAction("Não criamos projetos nem ativamos billing. Limites e custos dependem da sua conta."))
			b.WriteString(logAction("Tier informado pela API: " + m.projectTier))
			b.WriteString(logAction(m.projectInput.View()))
			if m.projectError != "" {
				b.WriteString(logAction(red.Render(m.projectError)))
			}
			b.WriteString(logAction("enter: usar este Project ID · esc: voltar à autenticação"))
		}

		// project
		if m.step > stepVerify && m.project != "" {
			b.WriteString(logLine("auth", fmt.Sprintf("project: %s", m.project), true))
			b.WriteString("\n")
		}

		// install
		if m.installed {
			b.WriteString(logLine("inst", "installed gsearch-mcp", true))
			b.WriteString(logAction(dim.Render("copied server binary to ~/.gsearch/")))
			if !m.useAPIKey {
				b.WriteString(logAction(dim.Render("credenciais OAuth em ~/.gsearch/oauth_creds.json")))
			}
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
			if m.testText != "" {
				preview := m.testText
				if len(preview) > 400 {
					preview = preview[:400] + "..."
				}
				width := m.width - 4
				if width < 40 {
					width = 40
				}
				for _, line := range strings.Split(strings.TrimSpace(preview), "\n") {
					for _, wrapped := range wrapLine(line, width) {
						b.WriteString(logAction(dim.Render(wrapped)))
					}
				}
			}
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
