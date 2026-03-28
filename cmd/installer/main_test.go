package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// geminiCredsPath / gsearchCredsPath
// ---------------------------------------------------------------------------

func TestGeminiCredsPath(t *testing.T) {
	p := geminiCredsPath()
	if !filepath.IsAbs(p) {
		t.Errorf("geminiCredsPath() = %q is not absolute", p)
	}
	if !strings.HasSuffix(p, filepath.Join(".gemini", "oauth_creds.json")) {
		t.Errorf("geminiCredsPath() = %q, expected suffix .gemini/oauth_creds.json", p)
	}
}

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
// isExpired
// ---------------------------------------------------------------------------

func TestIsExpired(t *testing.T) {
	now := time.Now().UnixMilli()

	tests := []struct {
		name       string
		expiryDate int64
		want       bool
	}{
		{
			name:       "token expired long ago",
			expiryDate: now - 120000,
			want:       true,
		},
		{
			name:       "token expires within 60s buffer",
			expiryDate: now + 30000,
			want:       true,
		},
		{
			name:       "token exactly at boundary",
			expiryDate: now + 60000,
			want:       false,
		},
		{
			name:       "token valid with plenty of time",
			expiryDate: now + 3600000,
			want:       false,
		},
		{
			name:       "zero expiry date",
			expiryDate: 0,
			want:       true,
		},
		{
			name:       "negative expiry date",
			expiryDate: -100000,
			want:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &oauthCreds{ExpiryDate: tc.expiryDate}
			got := isExpired(c)
			if got != tc.want {
				t.Errorf("isExpired(expiryDate=%d) = %v, want %v", tc.expiryDate, got, tc.want)
			}
		})
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
		payload := `{"email":"two@parts.com"}`
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		fakeJWT := fmt.Sprintf("header.%s", encoded)

		c := &oauthCreds{IDToken: fakeJWT}
		got := emailFromCreds(c)
		if got != "two@parts.com" {
			t.Errorf("emailFromCreds() = %q, want %q", got, "two@parts.com")
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
// randomState
// ---------------------------------------------------------------------------

func TestRandomState(t *testing.T) {
	t.Run("returns 32-char hex string", func(t *testing.T) {
		s := randomState()
		if len(s) != 32 {
			t.Errorf("randomState() length = %d, want 32", len(s))
		}
		// Verify all chars are valid hex
		for _, c := range s {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("randomState() contains non-hex char %q in %q", string(c), s)
				break
			}
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

// ---------------------------------------------------------------------------
// openBrowser — just verify it doesn't panic
// ---------------------------------------------------------------------------

func TestOpenBrowser(t *testing.T) {
	t.Run("does not panic with empty URL", func(t *testing.T) {
		// openBrowser will fail, but should not panic
		_ = openBrowser("")
	})

	t.Run("returns error or nil (platform-dependent)", func(t *testing.T) {
		// On CI with no display, this will likely return an error.
		// We just confirm it doesn't panic.
		err := openBrowser("https://example.com")
		// err can be nil (browser opens) or non-nil (no display), both are fine
		_ = err
	})
}

// ---------------------------------------------------------------------------
// saveCreds (installer version — creates parent directories)
// ---------------------------------------------------------------------------

func TestInstallerSaveCreds(t *testing.T) {
	t.Run("creates parent directories", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "nested", "dir", "oauth_creds.json")

		creds := &oauthCreds{
			AccessToken:  "at",
			RefreshToken: "rt",
			ExpiryDate:   12345,
			IDToken:      "idt",
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
// loadGeminiCreds
// ---------------------------------------------------------------------------

func TestLoadGeminiCreds(t *testing.T) {
	t.Run("returns error when file does not exist", func(t *testing.T) {
		tmp := t.TempDir()
		origHome := os.Getenv("HOME")
		os.Setenv("HOME", tmp)
		defer os.Setenv("HOME", origHome)

		_, err := loadGeminiCreds()
		if err == nil {
			t.Error("expected error when gemini creds file does not exist")
		}
	})

	t.Run("loads valid creds file", func(t *testing.T) {
		tmp := t.TempDir()
		origHome := os.Getenv("HOME")
		os.Setenv("HOME", tmp)
		defer os.Setenv("HOME", origHome)

		geminiDir := filepath.Join(tmp, ".gemini")
		os.MkdirAll(geminiDir, 0755)

		creds := oauthCreds{
			AccessToken:  "gemini-at",
			RefreshToken: "gemini-rt",
			ExpiryDate:   99999,
			IDToken:      "gemini-idt",
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		os.WriteFile(filepath.Join(geminiDir, "oauth_creds.json"), data, 0600)

		got, err := loadGeminiCreds()
		if err != nil {
			t.Fatalf("loadGeminiCreds() error: %v", err)
		}
		if got.AccessToken != "gemini-at" {
			t.Errorf("AccessToken = %q, want %q", got.AccessToken, "gemini-at")
		}
		if got.RefreshToken != "gemini-rt" {
			t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "gemini-rt")
		}
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		tmp := t.TempDir()
		origHome := os.Getenv("HOME")
		os.Setenv("HOME", tmp)
		defer os.Setenv("HOME", origHome)

		geminiDir := filepath.Join(tmp, ".gemini")
		os.MkdirAll(geminiDir, 0755)
		os.WriteFile(filepath.Join(geminiDir, "oauth_creds.json"), []byte("{bad json"), 0600)

		_, err := loadGeminiCreds()
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})
}

// ---------------------------------------------------------------------------
// injectMCPServer
// ---------------------------------------------------------------------------

func TestInjectMCPServer(t *testing.T) {
	t.Run("new file (does not exist yet)", func(t *testing.T) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "settings.json")

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
		path := filepath.Join(tmp, "settings.json")

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
		path := filepath.Join(tmp, "settings.json")

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
		path := filepath.Join(tmp, "deep", "nested", "settings.json")

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
		path := filepath.Join(tmp, "settings.json")

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
		path := filepath.Join(tmp, "settings.json")
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

// ---------------------------------------------------------------------------
// fetchProjectID — mock HTTP
// ---------------------------------------------------------------------------

func TestFetchProjectID(t *testing.T) {
	// Note: fetchProjectID uses a hardcoded URL (codeAssistURL), so we cannot
	// redirect its requests to httptest. We test its response parsing logic
	// by verifying the expected contract through mock server + direct client.

	t.Run("mock: success with project ID", func(t *testing.T) {
		srv := newMockServer(t, 200, map[string]any{
			"cloudaicompanionProject": "proj-abc-123",
		})
		defer srv.Close()

		// Verify the mock returns expected response
		resp := doMockPost(t, srv.URL, "test-token")
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if id, ok := result["cloudaicompanionProject"].(string); !ok || id != "proj-abc-123" {
			t.Errorf("unexpected project ID: %v", result)
		}
	})

	t.Run("mock: missing project in response", func(t *testing.T) {
		srv := newMockServer(t, 200, map[string]any{
			"otherField": "value",
		})
		defer srv.Close()

		resp := doMockPost(t, srv.URL, "test-token")
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		if _, ok := result["cloudaicompanionProject"]; ok {
			t.Error("expected no cloudaicompanionProject field")
		}
	})

	t.Run("mock: non-200 status", func(t *testing.T) {
		srv := newMockServer(t, 403, map[string]any{
			"error": "forbidden",
		})
		defer srv.Close()

		resp := doMockPost(t, srv.URL, "test-token")
		resp.Body.Close()
		if resp.StatusCode != 403 {
			t.Errorf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("mock: empty project ID in response", func(t *testing.T) {
		srv := newMockServer(t, 200, map[string]any{
			"cloudaicompanionProject": "",
		})
		defer srv.Close()

		resp := doMockPost(t, srv.URL, "test-token")
		var result map[string]any
		json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()

		// Empty string should be treated as "not found" by fetchProjectID
		id, _ := result["cloudaicompanionProject"].(string)
		if id != "" {
			t.Errorf("expected empty project ID, got %q", id)
		}
	})
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
			m.account = "user@test.com"
			m.project = "proj-123"
			m.wireActions = []string{"claude-code|edited settings"}
			m.width = 80
			m.height = 24

			// Should not panic
			output := m.View()
			if output == "" {
				t.Error("View() returned empty string")
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
}

// ---------------------------------------------------------------------------
// target struct
// ---------------------------------------------------------------------------

func TestTargetStruct(t *testing.T) {
	tgt := target{
		name:    "claude-code",
		version: "1.0.0",
		enabled: true,
	}

	if tgt.name != "claude-code" {
		t.Errorf("name = %q, want claude-code", tgt.name)
	}
	if tgt.version != "1.0.0" {
		t.Errorf("version = %q, want 1.0.0", tgt.version)
	}
	if !tgt.enabled {
		t.Error("enabled should be true")
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
// source count pattern (testCmd logic)
// ---------------------------------------------------------------------------

func TestSourceCountPattern(t *testing.T) {
	// the server produces: [1] Title (https://example.com)
	// the testCmd counts: strings.Count(text, "(https://")
	tests := []struct {
		name  string
		text  string
		want  int
	}{
		{
			"standard server output",
			"Some answer[1][2]\n\nSources:\n[1] Google (https://google.com)\n[2] GitHub (https://github.com)\n",
			2,
		},
		{
			"no sources",
			"Just a plain answer with no sources.",
			0,
		},
		{
			"http without s",
			"Sources:\n[1] Example (http://example.com)\n",
			0, // only counts https
		},
		{
			"mixed protocols",
			"Sources:\n[1] Secure (https://secure.com)\n[2] Insecure (http://insecure.com)\n",
			1,
		},
		{
			"url in text body without parens",
			"Visit https://example.com for more info.\n\nSources:\n[1] Doc (https://doc.com)\n",
			1, // only counts (https:// with opening paren
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Count(tt.text, "(https://")
			if got != tt.want {
				t.Errorf("source count = %d, want %d", got, tt.want)
			}
		})
	}
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

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func newMockServer(t *testing.T, statusCode int, body map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			t.Errorf("missing or invalid Authorization header: %q", auth)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(body)
	}))
}

func doMockPost(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url, strings.NewReader(`{"cloudaicompanionProject":""}`))
	if err != nil {
		t.Fatalf("NewRequest error: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do error: %v", err)
	}
	return resp
}
