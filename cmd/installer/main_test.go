package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// ---------------------------------------------------------------------------
// gsearchCredsPath
// ---------------------------------------------------------------------------

func TestGsearchCredsPath(t *testing.T) {
	p := gsearchCredsPath()
	if !filepath.IsAbs(p) {
		t.Errorf("gsearchCredsPath() = %q is not absolute", p)
	}
	if !strings.HasSuffix(p, filepath.Join(".gsearch", "oauth_creds.json")) {
		t.Errorf("gsearchCredsPath() = %q, expected suffix .gsearch/oauth_creds.json", p)
	}
}

// ---------------------------------------------------------------------------
// emailFromCreds
// ---------------------------------------------------------------------------

func TestEmailFromCreds(t *testing.T) {
	t.Run("valid JWT with email claim", func(t *testing.T) {
		payload := `{"email":"user@example.com","sub":"12345"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		fakeJWT := fmt.Sprintf("eyJhbGciOiJSUzI1NiJ9.%s.fake-sig", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "user@example.com" {
			t.Errorf("emailFromCreds() = %q, want %q", got, "user@example.com")
		}
	})

	t.Run("invalid base64 in payload", func(t *testing.T) {
		c := &oauthCreds{IDToken: "header.!!!not-base64!!!.sig"}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})

	t.Run("missing email claim", func(t *testing.T) {
		payload := `{"sub":"12345","name":"Test User"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		fakeJWT := fmt.Sprintf("header.%s.sig", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})

	t.Run("empty IDToken", func(t *testing.T) {
		c := &oauthCreds{IDToken: ""}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})

	t.Run("JWT with only one part (no dots)", func(t *testing.T) {
		c := &oauthCreds{IDToken: "single-part-no-dots"}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})

	t.Run("JWT with two parts (header.payload, no sig)", func(t *testing.T) {
		payload := `{"email":"two-parts@example.test"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		fakeJWT := fmt.Sprintf("header.%s", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "two-parts@example.test" {
			t.Errorf("emailFromCreds() = %q, want %q", got, "two-parts@example.test")
		}
	})

	t.Run("valid base64 but invalid JSON payload", func(t *testing.T) {
		encoded := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		fakeJWT := fmt.Sprintf("header.%s.sig", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})

	t.Run("email field is not a string", func(t *testing.T) {
		payload := `{"email":12345,"sub":"test"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		fakeJWT := fmt.Sprintf("header.%s.sig", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "" {
			t.Errorf("emailFromCreds() = %q, want empty", got)
		}
	})
}

// ---------------------------------------------------------------------------
// randomState / randomVerifier / pkceChallenge
// ---------------------------------------------------------------------------

func TestRandomState(t *testing.T) {
	t.Run("returns 43-char base64url string", func(t *testing.T) {
		s := randomState()
		if len(s) < 43 {
			t.Errorf("randomState() length = %d, want >= 43", len(s))
		}
		raw, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			t.Fatalf("randomState() = %q is not base64url: %v", s, err)
		}
		if len(raw) != 32 {
			t.Errorf("randomState() decodes to %d bytes, want 32", len(raw))
		}
	})

	t.Run("two calls return different values", func(t *testing.T) {
		s1 := randomState()
		s2 := randomState()
		if s1 == s2 {
			t.Errorf("two randomState() calls returned same value: %q", s1)
		}
	})

	t.Run("multiple calls all unique", func(t *testing.T) {
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			s := randomState()
			if seen[s] {
				t.Errorf("duplicate randomState() after %d calls: %q", i, s)
				break
			}
			seen[s] = true
		}
	})
}

func TestRandomVerifierAndChallenge(t *testing.T) {
	t.Run("verifier is 43-char base64url of 32 bytes", func(t *testing.T) {
		v := randomVerifier()
		if len(v) != 43 {
			t.Errorf("randomVerifier() length = %d, want 43", len(v))
		}
		raw, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("randomVerifier() = %q is not base64url: %v", v, err)
		}
		if len(raw) != 32 {
			t.Errorf("randomVerifier() decodes to %d bytes, want 32", len(raw))
		}
	})

	t.Run("challenge is S256 of verifier without padding", func(t *testing.T) {
		v := randomVerifier()
		got := pkceChallenge(v)
		sum := sha256.Sum256([]byte(v))
		want := base64.RawURLEncoding.EncodeToString(sum[:])
		if got != want {
			t.Errorf("pkceChallenge() = %q, want %q", got, want)
		}
		if strings.Contains(got, "=") {
			t.Errorf("pkceChallenge() = %q must not be padded", got)
		}
	})

	t.Run("two calls return different verifiers", func(t *testing.T) {
		if randomVerifier() == randomVerifier() {
			t.Error("two randomVerifier() calls returned same value")
		}
	})
}

// ---------------------------------------------------------------------------
// antigravity client metadata
// ---------------------------------------------------------------------------

func TestAntigravityUserAgent(t *testing.T) {
	arch := "amd64"
	if runtime.GOARCH == "arm64" {
		arch = "arm64"
	}
	want := fmt.Sprintf("antigravity/cli/1.4.6 (aidev_client; os_type=%s; arch=%s; cl=1005129088; auth_method=consumer)", runtime.GOOS, arch)
	if got := antigravityUserAgent(); got != want {
		t.Errorf("antigravityUserAgent() = %q, want %q", got, want)
	}
}

func TestCodeAssistBaseURL(t *testing.T) {
	t.Run("default daily host", func(t *testing.T) {
		t.Setenv("GSEARCH_ANTIGRAVITY_HOST", "")
		if got := codeAssistBaseURL(); got != "https://daily-cloudcode-pa.googleapis.com/v1internal" {
			t.Errorf("codeAssistBaseURL() = %q, want daily host", got)
		}
	})
	t.Run("prod env switches host", func(t *testing.T) {
		t.Setenv("GSEARCH_ANTIGRAVITY_HOST", "prod")
		if got := codeAssistBaseURL(); got != "https://cloudcode-pa.googleapis.com/v1internal" {
			t.Errorf("codeAssistBaseURL() = %q, want prod host", got)
		}
	})
	t.Run("unknown env values keep daily host", func(t *testing.T) {
		t.Setenv("GSEARCH_ANTIGRAVITY_HOST", "staging")
		if got := codeAssistBaseURL(); got != "https://daily-cloudcode-pa.googleapis.com/v1internal" {
			t.Errorf("codeAssistBaseURL() = %q, want daily host", got)
		}
	})
}

// ---------------------------------------------------------------------------
// buildAuthURL
// ---------------------------------------------------------------------------

func TestBuildAuthURL(t *testing.T) {
	u, err := url.Parse(buildAuthURL("http://127.0.0.1:54570/callback", "state-abc", "challenge-xyz"))
	if err != nil {
		t.Fatalf("buildAuthURL() produced invalid URL: %v", err)
	}
	if u.Scheme != "https" || u.Host != "accounts.google.com" || u.Path != "/o/oauth2/auth" {
		t.Errorf("buildAuthURL() = %q, want accounts.google.com/o/oauth2/auth", u)
	}
	q := u.Query()
	if got := q.Get("client_id"); got != oauthClientID {
		t.Errorf("client_id = %q, want %q", got, oauthClientID)
	}
	if got := q.Get("redirect_uri"); got != "http://127.0.0.1:54570/callback" {
		t.Errorf("redirect_uri = %q", got)
	}
	if got := q.Get("response_type"); got != "code" {
		t.Errorf("response_type = %q, want code", got)
	}
	wantScopes := "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/aicode https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
	if got := q.Get("scope"); got != wantScopes {
		t.Errorf("scope = %q, want %q", got, wantScopes)
	}
	if got := q.Get("state"); got != "state-abc" {
		t.Errorf("state = %q", got)
	}
	if got := q.Get("access_type"); got != "offline" {
		t.Errorf("access_type = %q, want offline", got)
	}
	if got := q.Get("prompt"); got != "consent" {
		t.Errorf("prompt = %q, want consent", got)
	}
	if got := q.Get("code_challenge"); got != "challenge-xyz" {
		t.Errorf("code_challenge = %q", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
}

// ---------------------------------------------------------------------------
// openBrowser — just verify it doesn't panic
// ---------------------------------------------------------------------------

func TestOpenBrowser(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, u := range []string{"", "https://example.com"} {
		t.Run(u, func(t *testing.T) {
			if err := openBrowser(u); err == nil {
				t.Error("expected error with browser command unavailable")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// saveCreds (installer version — creates parent directories)
// ---------------------------------------------------------------------------

func TestInstallerSaveCreds(t *testing.T) {
	t.Run("tightens permissions of existing file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "oauth_creds.json")
		if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := saveCreds(path, &oauthCreds{AccessToken: "at"}); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Fatalf("permissions = %o, want 600", perm)
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "nested", "dir", "oauth_creds.json")

		creds := &oauthCreds{
			AccessToken:  "at",
			RefreshToken: "rt",
			ExpiryDate:   12345,
			IDToken:      "idt",
			Provider:     credsProvider,
		}

		if err := saveCreds(path, creds); err != nil {
			t.Fatalf("saveCreds() error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile() error: %v", err)
		}

		var loaded oauthCreds
		if err := json.Unmarshal(data, &loaded); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		if loaded.AccessToken != "at" {
			t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, "at")
		}
		if loaded.RefreshToken != "rt" {
			t.Errorf("RefreshToken = %q, want %q", loaded.RefreshToken, "rt")
		}
		if loaded.ExpiryDate != 12345 {
			t.Errorf("ExpiryDate = %d, want 12345", loaded.ExpiryDate)
		}
		if loaded.IDToken != "idt" {
			t.Errorf("IDToken = %q, want %q", loaded.IDToken, "idt")
		}
		if loaded.Provider != credsProvider {
			t.Errorf("Provider = %q, want %q", loaded.Provider, credsProvider)
		}
	})

	t.Run("file permissions are 0600", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "oauth_creds.json")

		creds := &oauthCreds{AccessToken: "test"}
		if err := saveCreds(path, creds); err != nil {
			t.Fatalf("saveCreds() error: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat error: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0600 {
			t.Errorf("file permissions = %o, want 0600", perm)
		}
	})

	t.Run("overwrites existing file", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "oauth_creds.json")

		creds1 := &oauthCreds{AccessToken: "first"}
		saveCreds(path, creds1)

		creds2 := &oauthCreds{AccessToken: "second"}
		if err := saveCreds(path, creds2); err != nil {
			t.Fatalf("saveCreds() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		var loaded oauthCreds
		json.Unmarshal(data, &loaded)
		if loaded.AccessToken != "second" {
			t.Errorf("AccessToken = %q, want %q", loaded.AccessToken, "second")
		}
	})
}

// ---------------------------------------------------------------------------
// startCallbackServer: authorize URL + callback handling
// ---------------------------------------------------------------------------

func resetOauthState() {
	oauthState.codeCh = nil
	oauthState.errCh = nil
	oauthState.srv = nil
	oauthState.url = ""
	oauthState.state = ""
	oauthState.verifier = ""
	oauthState.redirectURI = ""
}

func shutdownOauthState() {
	if oauthState.srv != nil {
		oauthState.srv.Shutdown(context.Background())
	}
	resetOauthState()
}

func TestStartCallbackServerAuthURL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	if err := startCallbackServer(); err != nil {
		t.Fatalf("startCallbackServer() error: %v", err)
	}
	t.Cleanup(shutdownOauthState)

	u, err := url.Parse(oauthState.url)
	if err != nil {
		t.Fatalf("auth URL invalid: %v", err)
	}
	if u.Host != "accounts.google.com" || u.Path != "/o/oauth2/auth" {
		t.Errorf("auth URL = %q, want accounts.google.com/o/oauth2/auth", u)
	}

	q := u.Query()
	if got := q.Get("client_id"); got != oauthClientID {
		t.Errorf("client_id = %q, want antigravity client", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	state := q.Get("state")
	if len(state) < 43 {
		t.Errorf("state length = %d, want >= 43", len(state))
	}
	if state != oauthState.state {
		t.Errorf("state param %q does not match oauthState.state %q", state, oauthState.state)
	}
	sum := sha256.Sum256([]byte(oauthState.verifier))
	if got, want := q.Get("code_challenge"), base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Errorf("code_challenge = %q, want S256(verifier) = %q", got, want)
	}
	if len(oauthState.verifier) != 43 {
		t.Errorf("verifier length = %d, want 43", len(oauthState.verifier))
	}

	redirect := q.Get("redirect_uri")
	ru, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("redirect_uri invalid: %v", err)
	}
	if ru.Scheme != "http" || ru.Hostname() != "127.0.0.1" || ru.Path != "/callback" {
		t.Errorf("redirect_uri = %q, want http://127.0.0.1:<port>/callback", redirect)
	}
	if ru.Port() == "" {
		t.Fatalf("redirect_uri %q has no port", redirect)
	}
	if redirect != oauthState.redirectURI {
		t.Errorf("redirect_uri %q does not match stored %q", redirect, oauthState.redirectURI)
	}

	t.Run("callback with wrong state is rejected with 401 and no code is delivered", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/callback?state=wrong&code=steal", ru.Port()))
		if err != nil {
			t.Fatalf("callback request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("wrong state status = %d, want 401", resp.StatusCode)
		}
		select {
		case err := <-oauthState.errCh:
			t.Errorf("invalid state must not abort the legitimate login: %v", err)
		default:
		}
		select {
		case code := <-oauthState.codeCh:
			t.Errorf("code %q delivered despite state mismatch; token must not be exchanged", code)
		default:
		}
	})

	t.Run("callback with correct state delivers code", func(t *testing.T) {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/callback?state=%s&code=abc", ru.Port(), url.QueryEscape(oauthState.state)))
		if err != nil {
			t.Fatalf("callback request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("correct state status = %d, want 200", resp.StatusCode)
		}
		select {
		case code := <-oauthState.codeCh:
			if code != "abc" {
				t.Errorf("code = %q, want abc", code)
			}
		default:
			t.Error("no code delivered")
		}
	})
}

// ---------------------------------------------------------------------------
// exchangeToken
// ---------------------------------------------------------------------------

func makeEmailJWT(email string) string {
	payload := map[string]any{"sub": "12345"}
	if email != "" {
		payload["email"] = email
	}
	raw, _ := json.Marshal(payload)
	return fmt.Sprintf("eyJhbGciOiJSUzI1NiJ9.%s.sig", base64.RawURLEncoding.EncodeToString(raw))
}

func tokenExchangeForm(code, redirectURI, verifier string) url.Values {
	return url.Values{
		"client_id":     {oauthClientID},
		"client_secret": {oauthClientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
}

func TestExchangeTokenSuccess(t *testing.T) {
	jwt := makeEmailJWT("user@example.com")
	mockInstallerHTTP(t, []installerHTTPStep{{
		method:   "POST",
		host:     "https://oauth2.googleapis.com",
		path:     "token",
		noAuth:   true,
		wantForm: tokenExchangeForm("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier"),
		body:     fmt.Sprintf(`{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"id_token":%q}`, jwt),
	}})

	msg := exchangeToken("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier")
	done, ok := msg.(authDoneMsg)
	if !ok {
		t.Fatalf("exchangeToken() = %#v, want authDoneMsg", msg)
	}
	if done.account != "user@example.com" {
		t.Errorf("account = %q, want user@example.com", done.account)
	}
	if done.accessToken != "at-1" {
		t.Errorf("accessToken = %q, want at-1", done.accessToken)
	}

	data, err := os.ReadFile(gsearchCredsPath())
	if err != nil {
		t.Fatalf("creds file not saved: %v", err)
	}
	var creds oauthCreds
	if err := json.Unmarshal(data, &creds); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if creds.Provider != "antigravity" {
		t.Errorf("provider = %q, want antigravity", creds.Provider)
	}
	if creds.AccessToken != "at-1" || creds.RefreshToken != "rt-1" || creds.IDToken != jwt {
		t.Errorf("creds fields = %+v", creds)
	}
	if creds.ExpiryDate <= time.Now().UnixMilli() {
		t.Errorf("expiry = %d, want future", creds.ExpiryDate)
	}
}

func TestExchangeTokenRequiresRefreshToken(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{{
		method:   "POST",
		host:     "https://oauth2.googleapis.com",
		path:     "token",
		noAuth:   true,
		wantForm: tokenExchangeForm("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier"),
		body:     `{"access_token":"at-1","expires_in":3600}`,
	}})

	msg := exchangeToken("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier")
	failed, ok := msg.(errMsg)
	if !ok {
		t.Fatalf("exchangeToken() = %#v, want errMsg", msg)
	}
	if !strings.Contains(failed.err.Error(), "refresh_token") {
		t.Errorf("error = %q, want mention of refresh_token", failed.err)
	}
	if _, err := os.Stat(gsearchCredsPath()); !os.IsNotExist(err) {
		t.Errorf("creds file must not be saved without refresh_token: %v", err)
	}
}

func TestExchangeTokenUserinfoEmail(t *testing.T) {
	t.Run("userinfo fallback supplies email", func(t *testing.T) {
		mockInstallerHTTP(t, []installerHTTPStep{
			{
				method:   "POST",
				host:     "https://oauth2.googleapis.com",
				path:     "token",
				noAuth:   true,
				wantForm: tokenExchangeForm("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier"),
				body:     `{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600,"id_token":"header.e30.sig"}`,
			},
			{
				method:   "GET",
				host:     "https://www.googleapis.com",
				path:     "oauth2/v2/userinfo",
				wantAuth: "Bearer at-1",
				body:     `{"email":"info@example.com"}`,
			},
		})
		msg := exchangeToken("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier")
		done, ok := msg.(authDoneMsg)
		if !ok {
			t.Fatalf("exchangeToken() = %#v, want authDoneMsg", msg)
		}
		if done.account != "info@example.com" {
			t.Errorf("account = %q, want info@example.com", done.account)
		}
	})

	t.Run("userinfo HTTP failure is tolerated", func(t *testing.T) {
		mockInstallerHTTP(t, []installerHTTPStep{
			{
				method:   "POST",
				host:     "https://oauth2.googleapis.com",
				path:     "token",
				noAuth:   true,
				wantForm: tokenExchangeForm("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier"),
				body:     `{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}`,
			},
			{
				method:   "GET",
				host:     "https://www.googleapis.com",
				path:     "oauth2/v2/userinfo",
				wantAuth: "Bearer at-1",
				status:   500,
				body:     "boom",
			},
		})
		msg := exchangeToken("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier")
		done, ok := msg.(authDoneMsg)
		if !ok {
			t.Fatalf("exchangeToken() = %#v, want authDoneMsg", msg)
		}
		if done.account != "Conta Google" {
			t.Errorf("account = %q, want fallback Conta Google", done.account)
		}
	})

	t.Run("userinfo transport failure is tolerated", func(t *testing.T) {
		mockInstallerHTTP(t, []installerHTTPStep{
			{
				method:   "POST",
				host:     "https://oauth2.googleapis.com",
				path:     "token",
				noAuth:   true,
				wantForm: tokenExchangeForm("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier"),
				body:     `{"access_token":"at-1","refresh_token":"rt-1","expires_in":3600}`,
			},
			{
				method:     "GET",
				host:       "https://www.googleapis.com",
				path:       "oauth2/v2/userinfo",
				wantAuth:   "Bearer at-1",
				requestErr: errors.New("userinfo transport failure"),
			},
		})
		msg := exchangeToken("synthetic-code", "http://127.0.0.1:54570/callback", "synthetic-verifier")
		done, ok := msg.(authDoneMsg)
		if !ok {
			t.Fatalf("exchangeToken() = %#v, want authDoneMsg", msg)
		}
		if done.account != "Conta Google" {
			t.Errorf("account = %q, want fallback Conta Google", done.account)
		}
	})
}

// ---------------------------------------------------------------------------
// paste mode validates state
// ---------------------------------------------------------------------------

func TestPasteModeValidatesState(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{
		{
			method:   "POST",
			host:     "https://oauth2.googleapis.com",
			path:     "token",
			noAuth:   true,
			wantForm: tokenExchangeForm("paste-code", "http://127.0.0.1:54571/callback", "paste-verifier"),
			body:     `{"access_token":"at-2","refresh_token":"rt-2","expires_in":3600}`,
		},
		{
			method:   "GET",
			host:     "https://www.googleapis.com",
			path:     "oauth2/v2/userinfo",
			wantAuth: "Bearer at-2",
			body:     `{"email":"paste@example.com"}`,
		},
	})
	oauthState.state = "paste-state"
	oauthState.verifier = "paste-verifier"
	oauthState.redirectURI = "http://127.0.0.1:54571/callback"
	oauthState.codeCh = make(chan string, 1)
	oauthState.errCh = make(chan error, 1)
	oauthState.srv = &http.Server{}
	t.Cleanup(resetOauthState)

	m := initialModel()
	m.step = stepAuth
	m.authWaiting = true
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("v")})
	m = updated.(model)
	if !m.pasteMode {
		t.Fatal("pressing v did not open paste mode")
	}

	m.pasteInput.SetValue("http://127.0.0.1:54571/callback?state=wrong-state&code=steal-code")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if cmd != nil || m.pasteError == "" {
		t.Fatalf("pasted URL with divergent state must be rejected, got cmd=%v error=%q", cmd, m.pasteError)
	}

	m.pasteInput.SetValue("http://127.0.0.1:54571/callback?state=paste-state&code=paste-code")
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if cmd != nil {
		t.Fatal("paste must use the existing OAuth waiter instead of starting another exchange")
	}
	if len(oauthState.codeCh) != 1 {
		t.Fatal("valid callback URL did not notify the OAuth waiter")
	}
	done, ok := freshOAuthWait().(authDoneMsg)
	if !ok || done.accessToken != "at-2" || done.account != "paste@example.com" {
		t.Fatalf("exchange after paste = %#v, want authDoneMsg with at-2", done)
	}
}

// ---------------------------------------------------------------------------
// injectMCPServer
// ---------------------------------------------------------------------------

func TestInjectMCPServer(t *testing.T) {
	t.Run("new file (does not exist yet)", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".mcp.json")

		entry := map[string]any{
			"command": "/usr/bin/gsearch-server",
			"env":     map[string]string{"KEY": "val"},
		}

		if err := injectMCPServer(path, "gsearch", entry); err != nil {
			t.Fatalf("injectMCPServer() error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile error: %v", err)
		}

		var cfg map[string]any
		if err := json.Unmarshal(data, &cfg); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}

		servers, ok := cfg["mcpServers"].(map[string]any)
		if !ok {
			t.Fatal("mcpServers not found or wrong type")
		}

		gsearch, ok := servers["gsearch"].(map[string]any)
		if !ok {
			t.Fatal("gsearch entry not found")
		}

		if gsearch["command"] != "/usr/bin/gsearch-server" {
			t.Errorf("command = %v, want /usr/bin/gsearch-server", gsearch["command"])
		}
	})

	t.Run("existing file with other servers", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".mcp.json")

		existing := map[string]any{
			"mcpServers": map[string]any{
				"other-tool": map[string]any{
					"command": "/usr/bin/other",
				},
			},
			"someOtherKey": "preserved",
		}
		data, _ := json.MarshalIndent(existing, "", "  ")
		os.WriteFile(path, data, 0644)

		entry := map[string]any{
			"command": "/usr/bin/gsearch-server",
		}
		if err := injectMCPServer(path, "gsearch", entry); err != nil {
			t.Fatalf("injectMCPServer() error: %v", err)
		}

		data, _ = os.ReadFile(path)
		var cfg map[string]any
		json.Unmarshal(data, &cfg)

		servers := cfg["mcpServers"].(map[string]any)

		// Original server preserved
		if _, ok := servers["other-tool"]; !ok {
			t.Error("other-tool entry was lost")
		}
		// New server added
		if _, ok := servers["gsearch"]; !ok {
			t.Error("gsearch entry not added")
		}
		// Other keys preserved
		if cfg["someOtherKey"] != "preserved" {
			t.Error("someOtherKey was lost")
		}
	})

	t.Run("overwrite existing gsearch entry", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".mcp.json")

		existing := map[string]any{
			"mcpServers": map[string]any{
				"gsearch": map[string]any{
					"command": "/old/path",
				},
			},
		}
		data, _ := json.MarshalIndent(existing, "", "  ")
		os.WriteFile(path, data, 0644)

		entry := map[string]any{
			"command": "/new/path",
		}
		if err := injectMCPServer(path, "gsearch", entry); err != nil {
			t.Fatalf("injectMCPServer() error: %v", err)
		}

		data, _ = os.ReadFile(path)
		var cfg map[string]any
		json.Unmarshal(data, &cfg)

		servers := cfg["mcpServers"].(map[string]any)
		gsearch := servers["gsearch"].(map[string]any)
		if gsearch["command"] != "/new/path" {
			t.Errorf("command = %v, want /new/path", gsearch["command"])
		}
	})

	t.Run("creates parent directories if needed", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "deep", "nested", ".mcp.json")

		entry := map[string]any{"command": "/bin/test"}
		if err := injectMCPServer(path, "gsearch", entry); err != nil {
			t.Fatalf("injectMCPServer() error: %v", err)
		}

		if _, err := os.Stat(path); err != nil {
			t.Errorf("file was not created at %q: %v", path, err)
		}
	})

	t.Run("existing file without mcpServers key", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".mcp.json")

		existing := map[string]any{
			"someKey": "someValue",
		}
		data, _ := json.MarshalIndent(existing, "", "  ")
		os.WriteFile(path, data, 0644)

		entry := map[string]any{"command": "/bin/test"}
		if err := injectMCPServer(path, "gsearch", entry); err != nil {
			t.Fatalf("injectMCPServer() error: %v", err)
		}

		data, _ = os.ReadFile(path)
		var cfg map[string]any
		json.Unmarshal(data, &cfg)

		if cfg["someKey"] != "someValue" {
			t.Error("existing key was lost")
		}

		servers, ok := cfg["mcpServers"].(map[string]any)
		if !ok {
			t.Fatal("mcpServers not created")
		}
		if _, ok := servers["gsearch"]; !ok {
			t.Error("gsearch not added")
		}
	})

	t.Run("returns error for unparseable existing file", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".mcp.json")
		os.WriteFile(path, []byte("{bad json"), 0644)

		entry := map[string]any{"command": "/bin/test"}
		err := injectMCPServer(path, "gsearch", entry)
		if err == nil {
			t.Error("expected error for unparseable JSON")
		}
	})
}

// ---------------------------------------------------------------------------
// injectCodexMCP
// ---------------------------------------------------------------------------

func TestInjectCodexMCP(t *testing.T) {
	t.Run("new file (does not exist)", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, ".codex", "config.toml")

		if err := injectCodexMCP(path, "proj-123", "/home/user"); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile error: %v", err)
		}

		content := string(data)
		if !strings.Contains(content, "[mcp_servers.gsearch]") {
			t.Error("missing [mcp_servers.gsearch] section")
		}
		if !strings.Contains(content, "gsearch-server") {
			t.Error("missing gsearch-server command")
		}
		if !strings.Contains(content, "proj-123") {
			t.Error("missing project ID")
		}
	})

	t.Run("existing file with other content", func(t *testing.T) {
		tmp := t.TempDir()
		codexDir := filepath.Join(tmp, ".codex")
		os.MkdirAll(codexDir, 0755)
		path := filepath.Join(codexDir, "config.toml")

		existing := "[settings]\nmodel = \"gpt-4\"\n"
		os.WriteFile(path, []byte(existing), 0644)

		if err := injectCodexMCP(path, "proj-456", "/home/user"); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)

		// Original content preserved
		if !strings.Contains(content, "[settings]") {
			t.Error("existing [settings] section was lost")
		}
		if !strings.Contains(content, "model = \"gpt-4\"") {
			t.Error("existing model setting was lost")
		}
		// New section added
		if !strings.Contains(content, "[mcp_servers.gsearch]") {
			t.Error("missing [mcp_servers.gsearch] section")
		}
	})

	t.Run("replace existing gsearch block", func(t *testing.T) {
		tmp := t.TempDir()
		codexDir := filepath.Join(tmp, ".codex")
		os.MkdirAll(codexDir, 0755)
		path := filepath.Join(codexDir, "config.toml")

		// The removal logic skips lines from [mcp_servers.gsearch] until the
		// next "[" header. Since [mcp_servers.gsearch.env] starts with "[",
		// skip stops there, so only the main section header and its direct
		// key-value lines (e.g. command = ...) are removed. The env sub-section
		// lines remain as orphans. We test the actual behavior of the function.
		existing := `[settings]
model = "gpt-4"

[mcp_servers.gsearch]
command = "/old/path/gsearch-server"

[other_section]
key = "value"
`
		os.WriteFile(path, []byte(existing), 0644)

		if err := injectCodexMCP(path, "new-project", "/home/newuser"); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)

		// Old gsearch command line should be removed
		if strings.Contains(content, "/old/path/") {
			t.Error("old path still present")
		}

		// New gsearch should be present
		if !strings.Contains(content, "new-project") {
			t.Error("new project ID not found")
		}
		if !strings.Contains(content, "/home/newuser/.gsearch/gsearch-server") {
			t.Error("new server path not found")
		}

		// Other sections preserved
		if !strings.Contains(content, "[settings]") {
			t.Error("[settings] section was lost")
		}
		if !strings.Contains(content, "[other_section]") {
			t.Error("[other_section] was lost")
		}
	})

	t.Run("creates parent directories", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "deep", "nested", "config.toml")

		if err := injectCodexMCP(path, "proj", "/home/user"); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		if _, err := os.Stat(path); err != nil {
			t.Errorf("file not created: %v", err)
		}
	})

	t.Run("replace gsearch block that is the only content", func(t *testing.T) {
		tmp := t.TempDir()
		codexDir := filepath.Join(tmp, ".codex")
		os.MkdirAll(codexDir, 0755)
		path := filepath.Join(codexDir, "config.toml")

		existing := `[mcp_servers.gsearch]
command = "/old/gsearch-server"
[mcp_servers.gsearch.env]
GSEARCH_PROJECT = "old"
`
		os.WriteFile(path, []byte(existing), 0644)

		if err := injectCodexMCP(path, "new", "/home/u"); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)

		if strings.Contains(content, "/old/gsearch-server") {
			t.Error("old server path still present")
		}
		if !strings.Contains(content, "[mcp_servers.gsearch]") {
			t.Error("new gsearch section not found")
		}
		if !strings.Contains(content, "new") {
			t.Error("new project not found")
		}
	})
}

// ---------------------------------------------------------------------------
// initialModel
// ---------------------------------------------------------------------------

func TestInitialModel(t *testing.T) {
	m := initialModel()

	if m.step != stepBolt {
		t.Errorf("step = %v, want stepBolt (%v)", m.step, stepBolt)
	}
	if !m.scopeUser {
		t.Error("scopeUser should be true by default")
	}
	if m.scopeProject {
		t.Error("scopeProject should be false by default")
	}
	if m.cursor != 0 {
		t.Errorf("cursor = %d, want 0", m.cursor)
	}
	if m.authCursor != 0 {
		t.Errorf("authCursor = %d, want 0", m.authCursor)
	}
	if m.err != nil {
		t.Errorf("err = %v, want nil", m.err)
	}
}

func TestFetchProjectIDEnvPrecedence(t *testing.T) {
	tests := []struct {
		name    string
		gsearch string
		cloud   string
		cloudID string
		want    string
	}{
		{"gsearch wins", "gsearch-project", "cloud-project", "cloud-id", "gsearch-project"},
		{"cloud fallback", "", "cloud-project", "cloud-id", "cloud-project"},
		{"cloud ID fallback", "", "", "cloud-id", "cloud-id"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockInstallerHTTP(t, nil)
			t.Setenv("GSEARCH_PROJECT", tc.gsearch)
			t.Setenv("GOOGLE_CLOUD_PROJECT", tc.cloud)
			t.Setenv("GOOGLE_CLOUD_PROJECT_ID", tc.cloudID)
			got, err := fetchProjectID("test-token")
			if err != nil || got != tc.want {
				t.Fatalf("fetchProjectID() = %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestFetchProjectID(t *testing.T) {
	tests := []struct {
		name          string
		loadResponse  string
		want          string
		wantErr       string
		validationURL string
		onboard       bool
	}{
		{
			name:         "loadCodeAssist project",
			loadResponse: `{"cloudaicompanionProject":"proj-abc-123"}`,
			want:         "proj-abc-123",
		},
		{
			name:          "validation required",
			loadResponse:  `{"ineligibleTiers":[{"reasonCode":"VALIDATION_REQUIRED","validationUrl":"https://example.com/verify"}],"allowedTiers":[{"id":"free-tier","isDefault":true}]}`,
			validationURL: "https://example.com/verify",
		},
		{
			name:         "tier requires project",
			loadResponse: `{"allowedTiers":[{"id":"paid-tier","isDefault":true,"userDefinedCloudaicompanionProject":true}]}`,
			wantErr:      "exige o env GSEARCH_PROJECT ou GOOGLE_CLOUD_PROJECT",
		},
		{
			name:         "missing project and tiers",
			loadResponse: `{}`,
			wantErr:      "nenhum tier elegível",
		},
		{
			name:         "empty project and tiers",
			loadResponse: `{"cloudaicompanionProject":"","allowedTiers":[]}`,
			wantErr:      "nenhum tier elegível",
		},
		{
			name:         "onboarding with default tier",
			loadResponse: `{"allowedTiers":[{"id":"paid-tier","userDefinedCloudaicompanionProject":true},{"id":"free-tier","isDefault":true}]}`,
			want:         "onboard-project",
			onboard:      true,
		},
		{
			name:         "onboarding with first tier fallback",
			loadResponse: `{"allowedTiers":[{"id":"free-tier"}]}`,
			want:         "onboard-project",
			onboard:      true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			steps := []installerHTTPStep{{method: "POST", path: "v1internal:loadCodeAssist", body: tc.loadResponse}}
			if tc.onboard {
				steps = append(steps,
					installerHTTPStep{method: "POST", path: "v1internal:onboardUser", body: `{"name":"operations/test"}`},
					installerHTTPStep{method: "GET", path: "v1internal/operations/test", body: `{"done":true,"response":{"cloudaicompanionProject":{"id":"onboard-project"}}}`},
				)
			}
			mockInstallerHTTP(t, steps)
			got, err := fetchProjectID("test-token")
			if tc.validationURL != "" {
				var ve *validationError
				if got != "" || !errors.As(err, &ve) || ve.url != tc.validationURL {
					t.Fatalf("fetchProjectID() = %q, %v; want validationError with URL %q", got, err, tc.validationURL)
				}
				return
			}
			if tc.wantErr != "" {
				if got != "" || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("fetchProjectID() = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				if tc.name == "tier requires project" {
					var pe *projectRequiredError
					if !errors.As(err, &pe) || pe.tierID != "paid-tier" {
						t.Errorf("want typed projectRequiredError for paid-tier, got %v", err)
					}
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("fetchProjectID() = %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestProjectLookupErrors(t *testing.T) {
	readErr := errors.New("test response read failure")
	transportErr := errors.New("test transport failure")
	stages := []struct {
		name   string
		prefix []installerHTTPStep
		step   installerHTTPStep
	}{
		{
			name: "loadCodeAssist",
			step: installerHTTPStep{method: "POST", path: "v1internal:loadCodeAssist", body: `{"cloudaicompanionProject":"must-not-return"}`},
		},
		{
			name:   "onboardUser",
			prefix: []installerHTTPStep{{method: "POST", path: "v1internal:loadCodeAssist", body: `{"allowedTiers":[{"id":"free-tier","isDefault":true}]}`}},
			step:   installerHTTPStep{method: "POST", path: "v1internal:onboardUser", body: `{"name":"operations/test"}`},
		},
		{
			name: "pollOperation",
			prefix: []installerHTTPStep{
				{method: "POST", path: "v1internal:loadCodeAssist", body: `{"allowedTiers":[{"id":"free-tier","isDefault":true}]}`},
				{method: "POST", path: "v1internal:onboardUser", body: `{"name":"operations/test"}`},
			},
			step: installerHTTPStep{method: "GET", path: "v1internal/operations/test", body: `{"done":true,"response":{"cloudaicompanionProject":{"id":"must-not-return"}}}`},
		},
	}
	failures := []struct {
		name       string
		status     int
		body       string
		readErr    error
		requestErr error
		wantErr    string
	}{
		{name: "HTTP forbidden", status: 403, body: `{"error":{"message":"forbidden"}}`, wantErr: "403"},
		{name: "HTTP unavailable", status: 503, body: "unavailable", wantErr: "503"},
		{name: "invalid JSON", body: "{bad json", wantErr: "parse"},
		{name: "read error after valid JSON", readErr: readErr, wantErr: "read"},
		{name: "transport error", requestErr: transportErr, wantErr: "test transport failure"},
	}
	for _, stage := range stages {
		t.Run(stage.name, func(t *testing.T) {
			for _, failure := range failures {
				t.Run(failure.name, func(t *testing.T) {
					step := stage.step
					step.status = failure.status
					step.readErr = failure.readErr
					step.requestErr = failure.requestErr
					if failure.body != "" {
						step.body = failure.body
					}
					steps := append(append([]installerHTTPStep{}, stage.prefix...), step)
					mockInstallerHTTP(t, steps)
					start := time.Now()
					got, err := fetchProjectID("test-token")
					if got != "" || err == nil || !strings.Contains(err.Error(), failure.wantErr) {
						t.Fatalf("fetchProjectID() = %q, %v; want error containing %q", got, err, failure.wantErr)
					}
					if failure.readErr != nil && !errors.Is(err, failure.readErr) {
						t.Errorf("read error not preserved: %v", err)
					}
					if failure.requestErr != nil && !errors.Is(err, failure.requestErr) {
						t.Errorf("transport error not preserved: %v", err)
					}
					if failure.status != 0 && !strings.Contains(err.Error(), failure.body) {
						t.Errorf("HTTP response body missing from error: %v", err)
					}
					if elapsed := time.Since(start); elapsed >= 2*time.Second {
						t.Errorf("permanent failure took %v; should not wait for polling", elapsed)
					}
				})
			}
		})
	}
}

func TestOnboardUserAntigravityBody(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{
		{method: "POST", path: "v1internal:loadCodeAssist", body: `{"allowedTiers":[{"id":"paid-tier","isDefault":true}]}`},
		{
			method:   "POST",
			path:     "v1internal:onboardUser",
			wantBody: `{"tierId":"paid-tier","metadata":{"ideType":"ANTIGRAVITY"}}`,
			body:     `{"done":true,"response":{"cloudaicompanionProject":{"id":"paid-project"}}}`,
		},
	})
	got, err := fetchProjectID("test-token")
	if err != nil || got != "paid-project" {
		t.Fatalf("fetchProjectID() = %q, %v; want paid-project", got, err)
	}
}

func TestProdHostSwitch(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{
		{
			method: "POST",
			host:   "https://cloudcode-pa.googleapis.com",
			path:   "v1internal:loadCodeAssist",
			body:   `{"cloudaicompanionProject":"prod-project"}`,
		},
	})
	t.Setenv("GSEARCH_ANTIGRAVITY_HOST", "prod")
	got, err := fetchProjectID("test-token")
	if err != nil || got != "prod-project" {
		t.Fatalf("fetchProjectID() = %q, %v; want prod-project on prod host", got, err)
	}
}

func TestOnboardUserMissingOperation(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{{method: "POST", path: "v1internal:onboardUser", body: `{}`}})
	got, err := onboardUser("test-token", "free-tier")
	if got != "" || err == nil || !strings.Contains(err.Error(), "no operation name") {
		t.Fatalf("onboardUser() = %q, %v; want missing operation error", got, err)
	}
}

func TestPollOperation(t *testing.T) {
	tests := []struct {
		name    string
		bodies  []string
		want    string
		wantErr string
	}{
		{
			name:   "pending then success",
			bodies: []string{`{"done":false}`, `{"done":true,"response":{"cloudaicompanionProject":{"id":"poll-project"}}}`},
			want:   "poll-project",
		},
		{
			name:    "completed without project",
			bodies:  []string{`{"done":true,"response":{}}`},
			wantErr: "onboarding completed but no project ID",
		},
		{
			name:    "operation error before done",
			bodies:  []string{`{"done":false,"error":{"code":7,"message":"permission denied"}}`},
			wantErr: "operation error (code 7): permission denied",
		},
		{
			name:    "operation error overrides success",
			bodies:  []string{`{"done":true,"error":{"code":9,"message":"failed precondition"},"response":{"cloudaicompanionProject":{"id":"must-not-return"}}}`},
			wantErr: "operation error (code 9): failed precondition",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var steps []installerHTTPStep
			for _, body := range tc.bodies {
				steps = append(steps, installerHTTPStep{method: "GET", path: "v1internal/operations/test", body: body})
			}
			mockInstallerHTTP(t, steps)
			start := time.Now()
			got, err := pollOperation("test-token", "operations/test")
			if tc.wantErr != "" {
				if got != "" || err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("pollOperation() = %q, %v; want error containing %q", got, err, tc.wantErr)
				}
				if elapsed := time.Since(start); elapsed >= 2*time.Second {
					t.Errorf("permanent failure took %v; should not wait for polling", elapsed)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("pollOperation() = %q, %v; want %q, nil", got, err, tc.want)
			}
		})
	}
}

func TestExplicitProjectLookupNoHTTP(t *testing.T) {
	mockInstallerHTTP(t, nil)
	msg := projectLookupCmd("test-token", "cloud-project")()
	done, ok := msg.(projectDoneMsg)
	if !ok || done.project != "cloud-project" {
		t.Fatalf("projectLookupCmd(explicit) = %#v; want projectDoneMsg{cloud-project} without HTTP", msg)
	}
}

// ---------------------------------------------------------------------------
// View — smoke tests to ensure no panics
// ---------------------------------------------------------------------------

func TestViewNoPanic(t *testing.T) {
	steps := []step{
		stepBolt, stepDisclaimer, stepScan, stepTargets,
		stepScope, stepAuthChoice, stepAuth, stepProject,
		stepInstall, stepWire, stepTest, stepDone,
	}

	for _, s := range steps {
		t.Run(fmt.Sprintf("step_%d", s), func(t *testing.T) {
			m := initialModel()
			m.step = s
			m.targets = []target{
				{name: "claude-code", version: "1.0", enabled: true},
				{name: "codex-cli", version: "2.0", enabled: false},
			}
			m.account = "user@example.test"
			m.project = "proj-123"
			m.wireActions = []string{"claude-code|edited settings"}
			m.width = 80
			m.height = 24

			// Should not panic
			output := m.View()
			if output == "" {
				t.Error("View() returned empty string")
			}
			if s == stepScope {
				for _, path := range []string{"~/.claude.json", ".mcp.json"} {
					if !strings.Contains(output, path) {
						t.Errorf("scope view missing %q: %q", path, output)
					}
				}
				if strings.Contains(output, ".claude/settings.json") {
					t.Errorf("scope view shows obsolete MCP path: %q", output)
				}
			}
		})
	}

	t.Run("stepDone with error", func(t *testing.T) {
		m := initialModel()
		m.step = stepDone
		m.err = fmt.Errorf("test error")

		output := m.View()
		if !strings.Contains(output, "test error") {
			t.Errorf("error not shown in View(): %q", output)
		}
	})

	t.Run("stepAuth with authWaiting", func(t *testing.T) {
		m := initialModel()
		m.step = stepAuth
		m.authWaiting = true

		output := m.View()
		if !strings.Contains(output, "waiting") {
			t.Errorf("expected 'waiting' in output: %q", output)
		}
	})
}

// ---------------------------------------------------------------------------
// logLine / logAction
// ---------------------------------------------------------------------------

func TestLogLine(t *testing.T) {
	t.Run("with ok=true", func(t *testing.T) {
		line := logLine("scan", "found node", true)
		if !strings.Contains(line, "scan") {
			t.Errorf("logLine should contain tag 'scan': %q", line)
		}
		if !strings.Contains(line, "found node") {
			t.Errorf("logLine should contain message: %q", line)
		}
	})

	t.Run("with ok=false", func(t *testing.T) {
		line := logLine("auth", "waiting", false)
		if !strings.Contains(line, "auth") {
			t.Errorf("logLine should contain tag: %q", line)
		}
		if !strings.Contains(line, "waiting") {
			t.Errorf("logLine should contain message: %q", line)
		}
	})
}

func TestLogAction(t *testing.T) {
	action := logAction("some action")
	if !strings.Contains(action, "some action") {
		t.Errorf("logAction should contain message: %q", action)
	}
	// Should start with spaces for indentation
	if !strings.HasPrefix(action, "  ") {
		t.Errorf("logAction should start with indentation: %q", action)
	}
}

// ---------------------------------------------------------------------------
// oauthCreds JSON round-trip
// ---------------------------------------------------------------------------

func TestOauthCredsJSON(t *testing.T) {
	creds := oauthCreds{
		AccessToken:  "at-123",
		RefreshToken: "rt-456",
		ExpiryDate:   1700000000000,
		IDToken:      "idt-789",
		Provider:     credsProvider,
	}

	data, err := json.Marshal(creds)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var loaded oauthCreds
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if loaded != creds {
		t.Errorf("round-trip mismatch: got %+v, want %+v", loaded, creds)
	}
	if !strings.Contains(string(data), `"provider":"antigravity"`) {
		t.Errorf("provider field missing from JSON: %s", data)
	}
}

// ---------------------------------------------------------------------------
// injectCodexMCP — Windows backslash handling
// ---------------------------------------------------------------------------

func TestInjectCodexMCPWindowsPaths(t *testing.T) {
	t.Run("paths use single quotes (TOML literal strings)", func(t *testing.T) {
		tmp := t.TempDir()
		codexDir := filepath.Join(tmp, ".codex")
		path := filepath.Join(codexDir, "config.toml")

		if err := injectCodexMCP(path, "my-project", tmp); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)

		// should use single quotes (TOML literal strings) not double quotes
		if !strings.Contains(content, "command = '") {
			t.Errorf("expected single-quoted command, got:\n%s", content)
		}
		// should use forward slashes (filepath.ToSlash)
		if strings.Contains(content, "\\") {
			t.Errorf("expected forward slashes in path, got:\n%s", content)
		}
	})

	t.Run("path contains spaces", func(t *testing.T) {
		tmp := t.TempDir()
		home := filepath.Join(tmp, "User With Spaces")
		os.MkdirAll(home, 0755)
		codexDir := filepath.Join(home, ".codex")
		path := filepath.Join(codexDir, "config.toml")

		if err := injectCodexMCP(path, "my-project", home); err != nil {
			t.Fatalf("injectCodexMCP() error: %v", err)
		}

		data, _ := os.ReadFile(path)
		content := string(data)

		if !strings.Contains(content, "User With Spaces") {
			t.Errorf("path with spaces should be preserved:\n%s", content)
		}
	})
}

// ---------------------------------------------------------------------------
// truncateStr
// ---------------------------------------------------------------------------

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"empty", "", 10, ""},
		{"shorter", "hi", 10, "hi"},
		{"exact", "hello", 5, "hello"},
		{"longer", "hello world", 5, "hello..."},
		{"zero limit", "test", 0, "..."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateStr(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}

func TestScanCmdOtherside(t *testing.T) {
	for _, tc := range []struct {
		name    string
		script  string
		version string
		enabled bool
	}{
		{name: "absent"},
		{name: "present", script: "#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 9\nprintf '1.3.0\\n'\n", version: "1.3.0", enabled: true},
		{name: "prefixed version", script: "#!/bin/sh\n[ \"$1\" = \"--version\" ] || exit 9\nprintf 'otherside 1.3.0\\n'\n", version: "1.3.0", enabled: true},
		{name: "version fails", script: "#!/bin/sh\nexit 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin := t.TempDir()
			t.Setenv("HOME", t.TempDir())
			t.Setenv("PATH", bin)
			if tc.script != "" {
				if err := os.WriteFile(filepath.Join(bin, "otherside"), []byte(tc.script), 0755); err != nil {
					t.Fatal(err)
				}
			}
			msg := scanCmd().(scanDoneMsg)
			count := 0
			for _, target := range msg.targets {
				if target.name == "otherside" {
					count++
					if target.version != tc.version || target.enabled != tc.enabled {
						t.Errorf("Otherside = %+v; want version %q, enabled %v", target, tc.version, tc.enabled)
					}
				}
			}
			if count != 1 {
				t.Fatalf("Otherside targets = %d, want 1", count)
			}
		})
	}
}

func TestResolveOthersideMCPPath(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "User With Spaces")
	appData := filepath.Join(root, "Custom AppData")
	override := filepath.Join(root, "Custom Otherside")
	t.Setenv("HOME", home)
	t.Chdir(root)
	for _, tc := range []struct {
		name     string
		goos     string
		appData  string
		override string
		wantRoot string
	}{
		{name: "linux default", goos: "linux", wantRoot: filepath.Join(home, ".otherside")},
		{name: "mac default ignores APPDATA", goos: "darwin", appData: appData, wantRoot: filepath.Join(home, ".otherside")},
		{name: "windows APPDATA", goos: "windows", appData: appData, wantRoot: filepath.Join(appData, "Otherside")},
		{name: "windows home fallback", goos: "windows", wantRoot: filepath.Join(home, "AppData", "Roaming", "Otherside")},
		{name: "linux override", goos: "linux", override: override, wantRoot: override},
		{name: "mac override", goos: "darwin", override: override, wantRoot: override},
		{name: "windows override wins", goos: "windows", appData: appData, override: override, wantRoot: override},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTHERSIDE_CONFIG_DIR", tc.override)
			t.Setenv("APPDATA", tc.appData)
			want := filepath.Join(tc.wantRoot, ".mcp.json")
			if got := resolveOthersideMCPPath(home, tc.goos); got != want {
				t.Errorf("resolveOthersideMCPPath() = %q, want %q", got, want)
			}
			if os.Getenv("OTHERSIDE_CONFIG_DIR") != tc.override || os.Getenv("APPDATA") != tc.appData {
				t.Error("path resolution changed environment variables")
			}
		})
	}
}

func TestWireCmdClaudeScopes(t *testing.T) {
	for _, tc := range []struct {
		name            string
		user            bool
		project         bool
		existingProject bool
		standalone      bool
		standaloneFirst bool
	}{
		{name: "new project config", project: true},
		{name: "project preserves entries", project: true, existingProject: true},
		{name: "Claude then standalone preserves entries", project: true, existingProject: true, standalone: true},
		{name: "standalone then Claude preserves entries", project: true, existingProject: true, standalone: true, standaloneFirst: true},
		{name: "user scope stays in claude.json", user: true, existingProject: true},
		{name: "user and project scopes", user: true, project: true, existingProject: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "User With Spaces")
			work := filepath.Join(root, "project")
			for _, dir := range []string{home, filepath.Join(work, ".claude")} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Chdir(work)

			projectPath := filepath.Join(work, ".mcp.json")
			userPath := filepath.Join(home, ".claude.json")
			settingsPath := filepath.Join(work, ".claude", "settings.json")
			settings := "{\n  \"permissions\": {\"allow\": [\"Read\"]},\n  \"mcpServers\": {\"legacy\": {\"command\": \"leave-untouched\"}}\n}\n"
			original := map[string]string{
				userPath: `{"mcpServers":{"user-tool":{"command":"keep-user"}},"userSetting":"keep"}`,
			}
			if tc.existingProject {
				original[projectPath] = `{"mcpServers":{"other":{"command":"keep-project"},"gsearch":{"command":"old-server"}},"projectSetting":{"keep":true}}`
			}
			for path, content := range original {
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(settingsPath, []byte(settings), 0600); err != nil {
				t.Fatal(err)
			}

			targets := []target{{name: "claude-code", enabled: true}}
			if tc.standalone {
				standalone := target{name: "standalone (.mcp.json)", enabled: true}
				if tc.standaloneFirst {
					targets = append([]target{standalone}, targets...)
				} else {
					targets = append(targets, standalone)
				}
			}
			entry := map[string]any{
				"command": filepath.Join(home, ".gsearch", serverBinaryName()),
				"env":     map[string]any{"GSEARCH_PROJECT": "cloud-project"},
			}
			firstWrite := make(map[string]string)
			for run := 0; run < 2; run++ {
				msg := wireCmd(targets, tc.user, tc.project, "cloud-project")()
				done, ok := msg.(wireDoneMsg)
				if !ok {
					t.Fatalf("wireCmd() run %d = %#v, want wireDoneMsg", run, msg)
				}
				actions := strings.Join(done.actions, "\n")
				for _, scope := range []struct {
					path   string
					on     bool
					action string
				}{
					{userPath, tc.user, "claude-code|edited ~/.claude.json → added mcpServers.gsearch"},
					{projectPath, tc.project, "claude-code|edited .mcp.json → added mcpServers.gsearch"},
				} {
					if strings.Contains(actions, scope.action) != scope.on {
						t.Errorf("scope action %q enabled=%v, got %v", scope.action, scope.on, done.actions)
					}
					data, err := os.ReadFile(scope.path)
					if err != nil {
						t.Fatal(err)
					}
					if !scope.on {
						if string(data) != original[scope.path] {
							t.Errorf("unselected scope %s was changed: %s", scope.path, data)
						}
						continue
					}
					want := map[string]any{}
					if content := original[scope.path]; content != "" {
						if err := json.Unmarshal([]byte(content), &want); err != nil {
							t.Fatal(err)
						}
					}
					servers, ok := want["mcpServers"].(map[string]any)
					if !ok {
						servers = map[string]any{}
					}
					servers["gsearch"] = entry
					want["mcpServers"] = servers
					var got map[string]any
					if err := json.Unmarshal(data, &got); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("config %s = %v, want %v", scope.path, got, want)
					}
					if run == 0 {
						firstWrite[scope.path] = string(data)
					} else if string(data) != firstWrite[scope.path] {
						t.Errorf("config %s is not idempotent: %s", scope.path, data)
					}
				}
				if data, err := os.ReadFile(settingsPath); err != nil || string(data) != settings {
					t.Errorf("project .claude/settings.json was changed: %q, %v", data, err)
				}
				if strings.Contains(actions, ".claude/settings.json") {
					t.Errorf("wire actions show obsolete MCP path: %v", done.actions)
				}
			}
		})
	}
}

func TestWireCmdOtherside(t *testing.T) {
	for _, tc := range []struct {
		name       string
		enabled    bool
		standalone bool
		override   bool
		existing   string
		wantErr    bool
	}{
		{name: "new global config", enabled: true},
		{name: "override preserves entries", enabled: true, override: true, existing: `{"mcpServers":{"other":{"command":"keep-me"}},"userSetting":"keep"}`},
		{name: "preserves entries and is idempotent", enabled: true, existing: `{"mcpServers":{"other":{"command":"keep-me"}},"userSetting":"keep"}`},
		{name: "disabled", existing: `{"mcpServers":{"other":{"command":"keep-me"}}}`},
		{name: "invalid JSON", enabled: true, existing: "{bad json", wantErr: true},
		{name: "null config", enabled: true, existing: "null"},
		{name: "project standalone", standalone: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			home := filepath.Join(root, "User With Spaces")
			work := filepath.Join(root, "project")
			for _, dir := range []string{home, work} {
				if err := os.MkdirAll(dir, 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("PATH", t.TempDir())
			t.Setenv("OTHERSIDE_CONFIG_DIR", "")
			t.Setenv("APPDATA", "")
			if tc.override {
				t.Setenv("OTHERSIDE_CONFIG_DIR", filepath.Join(root, "Override With Spaces"))
			}
			t.Chdir(work)
			global := resolveOthersideMCPPath(home, runtime.GOOS)
			if tc.existing != "" {
				if err := os.MkdirAll(filepath.Dir(global), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(global, []byte(tc.existing), 0600); err != nil {
					t.Fatal(err)
				}
			}
			targets := []target{{name: "otherside", enabled: tc.enabled}}
			path := global
			if tc.standalone {
				targets = append(targets, target{name: "standalone (.mcp.json)", enabled: true})
				path = filepath.Join(work, ".mcp.json")
			}
			msg := wireCmd(targets, true, false, "cloud-project")()
			if tc.wantErr {
				errMsg, ok := msg.(errMsg)
				if !ok || !strings.Contains(errMsg.err.Error(), "Otherside") {
					t.Fatalf("wireCmd() = %#v, want Otherside JSON error", msg)
				}
				data, err := os.ReadFile(global)
				if err != nil || string(data) != tc.existing {
					t.Fatalf("invalid config was changed: %q, %v", data, err)
				}
				return
			}
			done, ok := msg.(wireDoneMsg)
			if !ok {
				t.Fatalf("wireCmd() = %#v, want wireDoneMsg", msg)
			}
			if !tc.enabled && !tc.standalone {
				data, err := os.ReadFile(global)
				if err != nil || string(data) != tc.existing || len(done.actions) != 0 {
					t.Fatalf("disabled target changed config: %q, %v, %+v", data, err, done)
				}
				return
			}
			if tc.enabled {
				if len(done.actions) != 1 || done.actions[0] != "otherside|configurado "+global {
					t.Errorf("Otherside action does not show actual config path: %v", done.actions)
				}
				if tc.override {
					t.Setenv("OTHERSIDE_CONFIG_DIR", "")
					defaultPath := resolveOthersideMCPPath(home, runtime.GOOS)
					t.Setenv("OTHERSIDE_CONFIG_DIR", filepath.Dir(global))
					if _, err := os.Stat(defaultPath); !os.IsNotExist(err) {
						t.Errorf("override unexpectedly wrote default config: %v", err)
					}
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err := json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			servers := cfg["mcpServers"].(map[string]any)
			want := map[string]any{
				"command": filepath.Join(home, ".gsearch", serverBinaryName()),
				"env":     map[string]any{"GSEARCH_PROJECT": "cloud-project"},
			}
			if !reflect.DeepEqual(servers["gsearch"], want) {
				t.Errorf("gsearch = %v, want %v", servers["gsearch"], want)
			}
			if strings.Contains(tc.existing, `"other"`) {
				if !reflect.DeepEqual(servers["other"], map[string]any{"command": "keep-me"}) || cfg["userSetting"] != "keep" {
					t.Errorf("existing configuration lost: %v", cfg)
				}
			}
			if msg := wireCmd(targets, true, false, "cloud-project")(); reflect.TypeOf(msg) != reflect.TypeOf(wireDoneMsg{}) {
				t.Fatalf("second wire failed: %#v", msg)
			}
			again, err := os.ReadFile(path)
			if err != nil || string(data) != string(again) {
				t.Errorf("wire is not idempotent: %q, %v", again, err)
			}
			for _, dir := range []string{"rules", "skills"} {
				if _, err := os.Stat(filepath.Join(filepath.Dir(global), dir)); !os.IsNotExist(err) {
					t.Errorf("unexpected Otherside %s: %v", dir, err)
				}
			}
			if tc.enabled {
				if _, err := os.Stat(filepath.Join(work, ".mcp.json")); !os.IsNotExist(err) {
					t.Errorf("global wiring unexpectedly wrote project config: %v", err)
				}
			}
		})
	}
}

func TestManualProjectFlow(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{{
		method: "POST",
		path:   "v1internal:loadCodeAssist",
		body:   `{"allowedTiers":[{"id":"standard-tier","isDefault":true,"userDefinedCloudaicompanionProject":true}]}`,
	}})
	m := initialModel()
	updated, cmd := m.Update(authDoneMsg{account: "test@example.com", accessToken: "test-token"})
	m = updated.(model)
	if cmd == nil {
		t.Fatal("missing project lookup command")
	}
	msg := cmd()
	needed, ok := msg.(projectNeededMsg)
	if !ok || needed.tierID != "standard-tier" {
		t.Fatalf("lookup = %#v; want projectNeededMsg for standard-tier", msg)
	}
	updated, _ = m.Update(msg)
	m = updated.(model)
	if !m.projectInputMode || m.step != stepProject || m.err != nil || m.installed {
		t.Fatalf("project input state = %+v", m)
	}
	view := m.View()
	for _, text := range []string{"Project ID do Google Cloud", "~/.gsearch/config.json", "não o número do projeto", "Tier informado pela API: standard-tier", "enter: usar este Project ID", "esc: voltar à autenticação"} {
		if !strings.Contains(view, text) {
			t.Errorf("project prompt missing %q", text)
		}
	}
	for _, banned := range []string{"legado", "Gemini CLI", "Antigravity CLI (AGY)", "migrar"} {
		if strings.Contains(view, banned) {
			t.Errorf("project prompt still shows legacy notice %q", banned)
		}
	}

	m.projectInput.SetValue("123456789012")
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if cmd != nil || m.projectError == "" {
		t.Fatal("numeric project number must be rejected before any submission")
	}

	m.projectInput.Reset()
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("cloud-project")})
	m = updated.(model)
	if m.projectInput.Value() != "cloud-project" {
		t.Fatalf("typed Project ID = %q", m.projectInput.Value())
	}
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if cmd == nil || m.installed {
		t.Fatal("expected pending manual project result, not installation")
	}
	// manual project must not trigger any HTTP call; the mock only allows the
	// initial loadCodeAssist step and asserts the total at cleanup
	done, ok := cmd().(projectDoneMsg)
	if !ok || done.project != "cloud-project" {
		t.Fatalf("manual project lookup = %#v", done)
	}
	updated, install := m.Update(done)
	m = updated.(model)
	if m.project != "cloud-project" || m.step != stepInstall || m.projectInputMode || m.installed || install == nil {
		t.Fatal("project success did not transition to pending installation")
	}
	if strings.Contains(m.View(), "installed gsearch-mcp") {
		t.Fatal("installation reported before installDoneMsg")
	}
	cfg := installerConfig(m)
	if cfg["auth_type"] != "oauth" || cfg["project"] != "cloud-project" {
		t.Fatalf("installerConfig() = %v, want oauth with project cloud-project", cfg)
	}
}

func TestManualProjectKeepsCredsUntouched(t *testing.T) {
	mockInstallerHTTP(t, nil)
	creds := &oauthCreds{AccessToken: "at", RefreshToken: "rt", Provider: credsProvider}
	if err := saveCreds(gsearchCredsPath(), creds); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(gsearchCredsPath())
	if err != nil {
		t.Fatal(err)
	}
	m := initialModel()
	m.accessToken = "at"
	updated, _ := m.Update(projectNeededMsg{tierID: "standard-tier"})
	m = updated.(model)
	m.projectInput.SetValue("cloud-project")
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if done, ok := cmd().(projectDoneMsg); !ok || done.project != "cloud-project" {
		t.Fatalf("manual project = %#v", done)
	}
	after, err := os.ReadFile(gsearchCredsPath())
	if err != nil || string(before) != string(after) {
		t.Fatalf("credentials changed: %q, %v", after, err)
	}
}

func TestProjectInputValidationAndEscape(t *testing.T) {
	mockInstallerHTTP(t, nil)
	m := initialModel()
	m.accessToken = "test-token"
	updated, _ := m.Update(projectNeededMsg{tierID: "standard-tier"})
	m = updated.(model)
	for _, value := range []string{"", "   ", "123456789012", " 123456789012 "} {
		m.projectInput.SetValue(value)
		updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
		m = updated.(model)
		if cmd != nil || m.projectError == "" || m.step != stepProject {
			t.Fatalf("invalid value %q triggered lookup or lost input", value)
		}
	}
	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(model)
	if cmd != nil || m.step != stepAuthChoice || m.projectInputMode || m.accessToken != "test-token" || m.installed {
		t.Fatal("Escape did not return to auth selection while preserving credentials")
	}
	m.authCursor = 1
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if !m.apiKeyMode || m.step != stepAuth || m.authWaiting {
		t.Fatal("API key selection started OAuth instead of key input")
	}
	m.apiKeyInput.SetValue("synthetic-api-key")
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if !m.useAPIKey || m.accessToken != "synthetic-api-key" || m.step != stepInstall || cmd == nil || m.installed {
		t.Fatal("API key did not transition to pending installation")
	}
	cfg := installerConfig(m)
	if cfg["auth_type"] != "api-key" || cfg["api_key"] != "synthetic-api-key" {
		t.Fatalf("installerConfig() = %v, want api-key config", cfg)
	}
}

func TestProjectVerificationFlowRetriesLoad(t *testing.T) {
	mockInstallerHTTP(t, []installerHTTPStep{
		{
			method: "POST",
			path:   "v1internal:loadCodeAssist",
			body:   `{"ineligibleTiers":[{"reasonCode":"VALIDATION_REQUIRED","validationUrl":"https://example.com/verify"}],"allowedTiers":[{"id":"free-tier","isDefault":true}]}`,
		},
		{
			method: "POST",
			path:   "v1internal:loadCodeAssist",
			body:   `{"cloudaicompanionProject":"verified-project"}`,
		},
	})
	t.Setenv("PATH", t.TempDir())
	msg := projectLookupCmd("test-token", "")()
	verify, ok := msg.(verifyNeededMsg)
	if !ok || verify.url != "https://example.com/verify" {
		t.Fatalf("lookup = %#v; want verifyNeededMsg with URL", msg)
	}
	m := initialModel()
	m.accessToken = "test-token"
	updated, cmd := m.Update(verify)
	m = updated.(model)
	if m.step != stepVerify || m.verifyURL != "https://example.com/verify" || cmd == nil {
		t.Fatal("verification state not entered")
	}
	if !strings.Contains(m.View(), "https://example.com/verify") {
		t.Fatal("verification URL not shown in view")
	}
	done, ok := cmd().(projectDoneMsg)
	if !ok || done.project != "verified-project" {
		t.Fatalf("verification retry = %#v; want verified-project", done)
	}
}

func TestAuthChoiceMenu(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())

	m := initialModel()
	m.step = stepAuthChoice
	view := m.View()
	for _, text := range []string{"Login Google (Antigravity)", "API key"} {
		if !strings.Contains(view, text) {
			t.Errorf("auth selection missing %q", text)
		}
	}
	for _, banned := range []string{"gemini", "Gemini", "legado", "~/.gemini"} {
		if strings.Contains(view, banned) {
			t.Errorf("auth selection still offers %q", banned)
		}
	}
	for _, step := range []step{stepBolt, stepAuthChoice} {
		m.step = step
		if strings.Contains(m.View(), "free google search") {
			t.Error("tagline still promises free search")
		}
	}
	m.step = stepAuthChoice

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(model)
	if m.authCursor != 1 {
		t.Fatalf("down moved authCursor to %d, want 1", m.authCursor)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(model)
	if m.authCursor != 1 {
		t.Fatalf("authCursor went past last option: %d", m.authCursor)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyUp})
	m = updated.(model)
	if m.authCursor != 0 {
		t.Fatalf("up moved authCursor to %d, want 0", m.authCursor)
	}

	updated, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if !m.authWaiting || m.step != stepAuth || cmd == nil {
		t.Fatal("first option did not start Antigravity OAuth")
	}
	msg := cmd()
	urlMsg, ok := msg.(authURLMsg)
	if !ok {
		t.Fatalf("freshOAuthStart() = %#v, want authURLMsg", msg)
	}
	if !strings.Contains(urlMsg.url, url.QueryEscape(oauthClientID)) {
		t.Errorf("auth URL %q does not use antigravity client", urlMsg.url)
	}
	shutdownOauthState()

	m = initialModel()
	m.step = stepAuthChoice
	m.authCursor = 1
	updated, cmd = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(model)
	if !m.apiKeyMode || m.step != stepAuth || m.authWaiting || cmd == nil {
		t.Fatal("second option did not open API key input")
	}

	m = initialModel()
	m.step = stepAuthChoice
	m.targets = []target{{name: "claude-code", enabled: true}}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(model)
	if m.step != stepScope {
		t.Fatalf("esc from auth choice went to %v, want stepScope", m.step)
	}
	m = initialModel()
	m.step = stepAuthChoice
	m.targets = []target{{name: "cursor", enabled: true}}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(model)
	if m.step != stepTargets {
		t.Fatalf("esc without claude went to %v, want stepTargets", m.step)
	}
}

func TestInstallAnnouncement(t *testing.T) {
	mockInstallerHTTP(t, nil)
	for _, step := range []step{stepProject, stepVerify, stepInstall, stepWire, stepDone} {
		m := initialModel()
		m.step = step
		m.err = errors.New("project lookup failed")
		if strings.Contains(m.View(), "installed gsearch-mcp") {
			t.Errorf("step %d falsely reports installed without flag", step)
		}
	}
	m := initialModel()
	updated, _ := m.Update(errMsg{err: errors.New("project lookup failed")})
	m = updated.(model)
	if m.installed || m.step != stepDone || strings.Contains(m.View(), "installed gsearch-mcp") {
		t.Fatal("error before installation falsely reports success")
	}
	for _, apiKey := range []bool{false, true} {
		m := initialModel()
		m.useAPIKey = apiKey
		m.step = stepInstall
		updated, _ := m.Update(installDoneMsg{})
		m = updated.(model)
		if !m.installed || m.step != stepWire || !strings.Contains(m.View(), "installed gsearch-mcp") {
			t.Fatal("installDoneMsg did not mark installation complete")
		}
		hasCredsLine := strings.Contains(m.View(), "oauth_creds.json")
		if hasCredsLine == apiKey {
			t.Errorf("oauth creds indication = %v for API key = %v", hasCredsLine, apiKey)
		}
	}
}

// ---------------------------------------------------------------------------
// HTTP mock (offline; swaps http.DefaultTransport)
// ---------------------------------------------------------------------------

type installerRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f installerRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type installerHTTPStep struct {
	method     string
	path       string
	host       string
	status     int
	body       string
	readErr    error
	requestErr error
	wantBody   string
	wantForm   url.Values
	wantAuth   string
	noAuth     bool
}

type installerTestBody struct {
	io.Reader
	readErr error
	closed  bool
}

func (b *installerTestBody) Read(p []byte) (int, error) {
	n, err := b.Reader.Read(p)
	if err == io.EOF && b.readErr != nil {
		return n, b.readErr
	}
	return n, err
}

func (b *installerTestBody) Close() error {
	b.closed = true
	return nil
}

const installerDailyHost = "https://daily-cloudcode-pa.googleapis.com"

func mockInstallerHTTP(t *testing.T, steps []installerHTTPStep) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, key := range []string{"GSEARCH_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID", "GSEARCH_ANTIGRAVITY_HOST"} {
		t.Setenv(key, "")
	}
	original := http.DefaultTransport
	calls := 0
	var bodies []*installerTestBody
	t.Cleanup(func() {
		http.DefaultTransport = original
		if calls != len(steps) {
			t.Errorf("HTTP calls = %d, want %d", calls, len(steps))
		}
		for i, body := range bodies {
			if !body.closed {
				t.Errorf("response body %d was not closed", i)
			}
		}
	})
	http.DefaultTransport = installerRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if calls >= len(steps) {
			t.Fatalf("unexpected HTTP request: %s %s", req.Method, req.URL)
		}
		step := steps[calls]
		calls++
		host := step.host
		if host == "" {
			host = installerDailyHost
		}
		wantURL := host + "/" + step.path
		if req.Method != step.method || req.URL.String() != wantURL {
			t.Fatalf("request = %s %s; want %s %s", req.Method, req.URL, step.method, wantURL)
		}
		if strings.HasPrefix(step.path, "v1internal") {
			if got := req.Header.Get("User-Agent"); got != antigravityUserAgent() {
				t.Errorf("User-Agent = %q, want %q", got, antigravityUserAgent())
			}
		}
		wantAuth := "Bearer test-token"
		if step.wantAuth != "" {
			wantAuth = step.wantAuth
		}
		if !step.noAuth {
			if got := req.Header.Get("Authorization"); got != wantAuth {
				t.Errorf("Authorization = %q, want %q", got, wantAuth)
			}
		}
		if req.Method == "POST" {
			defer req.Body.Close()
			payload, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("read request body: %v", err)
			}
			if step.wantForm != nil {
				if got := req.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
					t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got)
				}
				got, err := url.ParseQuery(string(payload))
				if err != nil {
					t.Fatalf("parse form body: %v", err)
				}
				if !reflect.DeepEqual(got, step.wantForm) {
					t.Errorf("form = %v, want %v", got, step.wantForm)
				}
			} else {
				if got := req.Header.Get("Content-Type"); got != "application/json" {
					t.Errorf("Content-Type = %q, want application/json", got)
				}
				var got, want map[string]any
				if err := json.Unmarshal(payload, &got); err != nil {
					t.Fatalf("decode request: %v", err)
				}
				wantJSON := `{"metadata":{"ideType":"ANTIGRAVITY"}}`
				if step.path == "v1internal:onboardUser" {
					wantJSON = `{"tierId":"free-tier","metadata":{"ideType":"ANTIGRAVITY"}}`
				}
				if step.wantBody != "" {
					wantJSON = step.wantBody
				}
				if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
					t.Fatalf("decode expected request: %v", err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("request body = %v, want %v", got, want)
				}
			}
		}
		if step.requestErr != nil {
			return nil, step.requestErr
		}
		status := step.status
		if status == 0 {
			status = http.StatusOK
		}
		body := &installerTestBody{Reader: strings.NewReader(step.body), readErr: step.readErr}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: status, Body: body, Header: make(http.Header)}, nil
	})
}
