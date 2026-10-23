package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func mockTransport(t *testing.T, fn roundTripFunc) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func isolateServer(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	for _, name := range []string{"GSEARCH_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID", "GEMINI_API_KEY", "GSEARCH_API_KEY", "GSEARCH_ANTIGRAVITY_HOST"} {
		t.Setenv(name, "")
	}
	previousCreds, previousProject, previousKey := cachedCreds, cachedProject, apiKey
	previousModels, previousSession := models, cachedSessionID
	previousConfigured, previousConfiguredProject := modelsConfigured, configuredProject
	previousSem, previousCooldown := apiSem, cooldownUntil
	cachedCreds, cachedProject, apiKey = nil, "", ""
	models, cachedSessionID = []string{defaultModel, fallbackModel}, "fake-session"
	modelsConfigured, configuredProject = false, ""
	apiSem, cooldownUntil = make(chan struct{}, 1), time.Time{}
	t.Cleanup(func() {
		cachedCreds, cachedProject, apiKey = previousCreds, previousProject, previousKey
		models, cachedSessionID = previousModels, previousSession
		modelsConfigured, configuredProject = previousConfigured, previousConfiguredProject
		apiSem, cooldownUntil = previousSem, previousCooldown
	})
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		t.Errorf("unexpected network request: %s %s", req.Method, req.URL.Redacted())
		return nil, errors.New("network disabled in test")
	})
}

func agyCreds(t *testing.T, token string) *oauthCreds {
	t.Helper()
	creds := &oauthCreds{AccessToken: token, RefreshToken: "fake-agy-refresh", ExpiryDate: time.Now().Add(time.Hour).UnixMilli(), Provider: "antigravity"}
	path := credsFiles()[0]
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveCreds(path, creds); err != nil {
		t.Fatal(err)
	}
	cachedCreds = creds
	return creds
}

func checkAgyHeaders(t *testing.T, req *http.Request, token string) {
	t.Helper()
	if req.Header.Get("Authorization") != "Bearer "+token {
		t.Fatalf("Authorization = %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("User-Agent") != agyUserAgent() {
		t.Fatalf("User-Agent = %q, want %q", req.Header.Get("User-Agent"), agyUserAgent())
	}
	if accept := req.Header.Get("Accept"); accept != "" {
		t.Fatalf("antigravity request must not send Accept, got %q", accept)
	}
}

type failingBody struct{}

func (failingBody) Read([]byte) (int, error) { return 0, errors.New("fake read error") }
func (failingBody) Close() error             { return nil }

func testResponse(status int, body string, readError bool) *http.Response {
	var reader io.ReadCloser = io.NopCloser(strings.NewReader(body))
	if readError {
		reader = failingBody{}
	}
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: reader}
}

func checkRequest(t *testing.T, req *http.Request, method, endpoint, token string) {
	t.Helper()
	if req.Method != method || req.URL.String() != endpoint {
		t.Fatalf("request = %s %s, want %s %s", req.Method, req.URL, method, endpoint)
	}
	wantAuth := ""
	if token != "" {
		wantAuth = "Bearer " + token
	}
	if req.Header.Get("Authorization") != wantAuth {
		t.Fatalf("unexpected Authorization: %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("x-goog-api-key") != apiKey {
		t.Fatalf("unexpected API key header: %q", req.Header.Get("x-goog-api-key"))
	}
	if req.URL.RawQuery != "" {
		t.Fatalf("unexpected query: %s", req.URL.RawQuery)
	}
}

func checkResult(t *testing.T, got string, err error, want, wantErr string) {
	t.Helper()
	if got != want {
		t.Fatalf("result = %q, want %q (error: %v)", got, want, err)
	}
	if wantErr == "" {
		if err != nil {
			t.Fatal(err)
		}
	} else if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Fatalf("error = %v, want substring %q", err, wantErr)
	}
}

func writeFakeCreds(t *testing.T, token string) *oauthCreds {
	t.Helper()
	creds := &oauthCreds{AccessToken: token, RefreshToken: "fake-refresh", ExpiryDate: time.Now().Add(time.Hour).UnixMilli()}
	path := credsFiles()[0]
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveCreds(path, creds); err != nil {
		t.Fatal(err)
	}
	return creds
}

func TestGoogleSearchAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		key, persistent, refreshFailure bool
		wantSearches, wantRefreshes     int
	}{
		{"401 refresh success", false, false, false, 2, 1},
		{"persistent 401", false, true, false, 2, 1},
		{"refresh failure", false, false, true, 1, 1},
		{"API key 401 without OAuth", true, true, false, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			if tc.key {
				apiKey = "fake-api-key"
			} else {
				cachedCreds = writeFakeCreds(t, "fake-rejected")
				cachedProject = "fake-project"
			}
			searches, refreshes := 0, 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				if req.URL.String() == tokenURL {
					refreshes++
					if err := req.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if req.PostForm.Get("refresh_token") != "fake-refresh" || req.PostForm.Get("grant_type") != "refresh_token" {
						t.Fatalf("unexpected refresh form: %v", req.PostForm)
					}
					if tc.refreshFailure {
						return testResponse(400, `{"error":"invalid_grant"}`, false), nil
					}
					return testResponse(200, `{"access_token":"fake-renewed","expires_in":3600}`, false), nil
				}
				searches++
				if tc.key {
					checkRequest(t, req, "POST", apiKeyEndpoint+"/models/"+defaultModel+":generateContent", "")
				} else {
					wantToken := "fake-rejected"
					if searches > 1 {
						wantToken = "fake-renewed"
					}
					checkRequest(t, req, "POST", oauthEndpoint+":generateContent", wantToken)
				}
				if searches == 1 || tc.persistent {
					return testResponse(401, `{"error":{"message":"rejected"}}`, false), nil
				}
				return testResponse(200, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`, false), nil
			})
			got, err := googleSearch(context.Background(), "fake query")
			if tc.refreshFailure {
				checkResult(t, got, err, "", "invalid_grant")
			} else if tc.persistent {
				checkResult(t, got, err, "", "API 401")
			} else {
				checkResult(t, got, err, "ok", "")
			}
			if searches != tc.wantSearches || refreshes != tc.wantRefreshes {
				t.Fatalf("searches = %d, refreshes = %d, want %d/%d", searches, refreshes, tc.wantSearches, tc.wantRefreshes)
			}
			if !tc.key && !tc.refreshFailure {
				creds, _, err := loadCreds()
				if err != nil || creds.AccessToken != "fake-renewed" {
					t.Fatalf("saved creds = %v, error = %v", creds, err)
				}
			}
		})
	}
}

func TestGoogleSearchProjectAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name                                   string
		projectStatus, searchStatus            int
		refreshFailure                         bool
		wantLoads, wantRefreshes, wantSearches int
		want, wantErr                          string
	}{
		{"project 401 refresh success", 200, 200, false, 2, 1, 1, "ok", ""},
		{"persistent project 401", 401, 200, false, 2, 1, 0, "", "loadCodeAssist 401"},
		{"project recovery then search 401", 200, 401, false, 2, 1, 1, "", "API 401"},
		{"project 403 without refresh", 403, 200, false, 1, 0, 0, "", "loadCodeAssist 403"},
		{"project refresh failure preserves cause", 200, 200, true, 1, 1, 0, "", "invalid_grant"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			cachedCreds = writeFakeCreds(t, "fake-rejected")
			loads, refreshes, searches := 0, 0, 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				switch req.URL.String() {
				case oauthEndpoint + ":loadCodeAssist":
					loads++
					wantToken := "fake-rejected"
					if loads > 1 {
						wantToken = "fake-renewed"
					}
					checkRequest(t, req, "POST", oauthEndpoint+":loadCodeAssist", wantToken)
					status := tc.projectStatus
					if loads == 1 && status != 403 {
						status = 401
					}
					if status != 200 {
						return testResponse(status, `{"error":{"message":"rejected"}}`, false), nil
					}
					return testResponse(200, `{"cloudaicompanionProject":"fake-project"}`, false), nil
				case tokenURL:
					refreshes++
					if loads != 1 || searches != 0 {
						t.Fatalf("unexpected refresh order: loads=%d searches=%d", loads, searches)
					}
					if err := req.ParseForm(); err != nil {
						t.Fatal(err)
					}
					if req.PostForm.Get("refresh_token") != "fake-refresh" {
						t.Fatalf("unexpected refresh token: %q", req.PostForm.Get("refresh_token"))
					}
					if tc.refreshFailure {
						return testResponse(400, `{"error":"invalid_grant"}`, false), nil
					}
					return testResponse(200, `{"access_token":"fake-renewed","expires_in":3600}`, false), nil
				case oauthEndpoint + ":generateContent":
					searches++
					checkRequest(t, req, "POST", oauthEndpoint+":generateContent", "fake-renewed")
					if loads != 2 {
						t.Fatalf("search before project discovery: loads=%d", loads)
					}
					if tc.searchStatus != 200 {
						return testResponse(tc.searchStatus, `{"error":{"message":"rejected"}}`, false), nil
					}
					return testResponse(200, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`, false), nil
				default:
					t.Fatalf("unexpected request: %s", req.URL)
					return nil, errors.New("unexpected request")
				}
			})
			got, err := googleSearch(context.Background(), "fake query")
			checkResult(t, got, err, tc.want, tc.wantErr)
			if loads != tc.wantLoads || refreshes != tc.wantRefreshes || searches != tc.wantSearches {
				t.Fatalf("loads/refreshes/searches = %d/%d/%d, want %d/%d/%d", loads, refreshes, searches, tc.wantLoads, tc.wantRefreshes, tc.wantSearches)
			}
			if strings.Contains(tc.wantErr, "loadCodeAssist") {
				var se searchError
				if !errors.As(err, &se) || se.status != tc.projectStatus {
					t.Fatalf("project error lost status: %v", err)
				}
			}
		})
	}
}

func TestGoogleSearchResponseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantErr string
		readError           bool
	}{
		{"malformed", `{invalid`, "decode search response", false},
		{"API error", `{"error":{"code":7,"message":"denied"}}`, "API error 7: denied", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			apiKey = "fake-api-key"
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				return testResponse(200, tc.body, tc.readError), nil
			})
			got, err := googleSearch(context.Background(), "fake query")
			checkResult(t, got, err, "", tc.wantErr)
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestInterruptedResponseRetries(t *testing.T) {
	isolateServer(t)
	apiKey = "fake-api-key"
	calls := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if calls == 1 {
			return testResponse(200, "", true), nil
		}
		return testResponse(200, `{"candidates":[{"content":{"parts":[{"text":"recovered"}]}}]}`, false), nil
	})
	got, err := googleSearch(context.Background(), "fake query")
	checkResult(t, got, err, "recovered", "")
	if calls != 2 {
		t.Fatalf("requests = %d, want 2", calls)
	}
}

func TestAPIKeyTransportError(t *testing.T) {
	isolateServer(t)
	apiKey = "fake-secret-api-key"
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		checkRequest(t, req, "POST", apiKeyEndpoint+"/models/"+defaultModel+":generateContent", "")
		return nil, errors.New("fake transport failure")
	})
	_, _, se, err := doSearch(context.Background(), "fake query", defaultModel, "", "")
	if err == nil || !strings.Contains(err.Error(), "fake transport failure") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), apiKey) || strings.Contains(se.message, apiKey) {
		t.Fatal("API key leaked into error")
	}
}

func TestGetToken(t *testing.T) {
	for _, tc := range []struct {
		name, cached, disk, rejected, want string
		wantRefreshes                      int
	}{
		{"valid cache", "fake-cached", "fake-disk", "", "fake-cached", 0},
		{"valid disk", "", "fake-disk", "", "fake-disk", 0},
		{"rejected cache and disk", "fake-old", "fake-old", "fake-old", "fake-renewed", 1},
		{"rejected disk", "", "fake-old", "fake-old", "fake-renewed", 1},
		{"already renewed cache", "fake-new", "fake-old", "fake-old", "fake-new", 0},
		{"already renewed disk", "fake-old", "fake-new", "fake-old", "fake-new", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			writeFakeCreds(t, tc.disk)
			if tc.cached != "" {
				cachedCreds = &oauthCreds{AccessToken: tc.cached, ExpiryDate: time.Now().Add(time.Hour).UnixMilli()}
			}
			refreshes := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				refreshes++
				if req.URL.String() != tokenURL {
					t.Fatalf("unexpected URL: %s", req.URL)
				}
				return testResponse(200, `{"access_token":"fake-renewed","expires_in":3600}`, false), nil
			})
			got, err := getToken(tc.rejected)
			checkResult(t, got, err, tc.want, "")
			if refreshes != tc.wantRefreshes {
				t.Fatalf("refreshes = %d, want %d", refreshes, tc.wantRefreshes)
			}
		})
	}
	t.Run("concurrent rejection refreshes once", func(t *testing.T) {
		isolateServer(t)
		cachedCreds = writeFakeCreds(t, "fake-old")
		refreshes := 0
		mockTransport(t, func(req *http.Request) (*http.Response, error) {
			refreshes++
			return testResponse(200, `{"access_token":"fake-renewed","expires_in":3600}`, false), nil
		})
		var wg sync.WaitGroup
		results := make(chan error, 8)
		for i := 0; i < cap(results); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				token, err := getToken("fake-old")
				if err == nil && token != "fake-renewed" {
					err = fmt.Errorf("token = %q", token)
				}
				results <- err
			}()
		}
		wg.Wait()
		close(results)
		for err := range results {
			if err != nil {
				t.Error(err)
			}
		}
		if refreshes != 1 {
			t.Fatalf("refreshes = %d, want 1", refreshes)
		}
	})
}

func TestRefreshToken(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantErr string
		status              int
		readError           bool
	}{
		{"success", `{"access_token":"fake-new","refresh_token":"fake-next","id_token":"fake-id","expires_in":3600}`, "", 200, false},
		{"read error", `{}`, "fake read error", 200, true},
		{"malformed", `{invalid`, "invalid character", 200, false},
		{"status", `{}`, "token refresh HTTP 400", 400, false},
		{"missing token", `{}`, "no access_token", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				deadline, ok := req.Context().Deadline()
				remaining := time.Until(deadline)
				if !ok || remaining <= 0 || remaining > 15*time.Second {
					t.Fatalf("refresh deadline remaining = %v, set = %v", remaining, ok)
				}
				if req.Method != "POST" || req.URL.String() != tokenURL {
					t.Fatalf("request = %s %s", req.Method, req.URL)
				}
				return testResponse(tc.status, tc.body, tc.readError), nil
			})
			creds := &oauthCreds{AccessToken: "fake-old", RefreshToken: "fake-refresh"}
			err := refreshToken(creds)
			checkResult(t, "", err, "", tc.wantErr)
			if tc.wantErr == "" && (creds.AccessToken != "fake-new" || creds.RefreshToken != "fake-next" || creds.IDToken != "fake-id" || isExpired(creds)) {
				t.Fatalf("unexpected refreshed credentials: %+v", creds)
			}
			if calls != 1 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}

func TestOnboardUser(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantErr string
		status              int
		readError           bool
	}{
		{"malformed", `{invalid`, "decode onboardUser", 200, false},
		{"status", `{}`, "onboardUser 403", 403, false},
		{"read error", `{}`, "fake read error", 200, true},
		{"operation error", `{"name":"operations/fake","done":true,"error":{"code":7,"message":"denied"}}`, "API error 7: denied", 200, false},
		{"missing operation", `{}`, "no operation name", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				checkRequest(t, req, "POST", oauthEndpoint+":onboardUser", "fake-token")
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["tierId"] != "free" || body["cloudaicompanionProject"] != "fake-project" {
					t.Fatalf("unexpected body: %v", body)
				}
				return testResponse(tc.status, tc.body, tc.readError), nil
			})
			got, err := onboardUser("fake-token", "free", "fake-project")
			checkResult(t, got, err, "", tc.wantErr)
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestPollOperation(t *testing.T) {
	for _, tc := range []struct {
		name, body, want, wantErr string
		status                    int
		readError                 bool
	}{
		{"success", `{"done":true,"response":{"cloudaicompanionProject":{"id":"fake-project"}}}`, "fake-project", "", 200, false},
		{"operation error", `{"done":true,"error":{"code":7,"message":"denied"},"response":{"cloudaicompanionProject":{"id":"ignore"}}}`, "", "API error 7: denied", 200, false},
		{"error before done", `{"done":false,"error":{"code":3,"message":"invalid"}}`, "", "API error 3: invalid", 200, false},
		{"status", `{"done":true,"response":{"cloudaicompanionProject":{"id":"ignore"}}}`, "", "operation HTTP 403", 403, false},
		{"malformed", `{invalid`, "", "decode operation response", 200, false},
		{"read error", `{}`, "", "fake read error", 200, true},
		{"no project", `{"done":true,"response":{}}`, "", "no project ID", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				checkRequest(t, req, "GET", oauthEndpoint+"/operations/fake", "fake-token")
				return testResponse(tc.status, tc.body, tc.readError), nil
			})
			got, err := pollOperation("fake-token", "operations/fake")
			checkResult(t, got, err, tc.want, tc.wantErr)
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
}

func TestRetryWait(t *testing.T) {
	for _, tc := range []struct {
		name, retryDelay string
		local, min, max  time.Duration
		explicit         bool
	}{
		{"explicit exactly default", "2s", time.Second, 2 * time.Second, 2 * time.Second, true},
		{"explicit above max", "45s", maxDelay, 45 * time.Second, 45 * time.Second, true},
		{"fractional seconds preserved", "1.950553118s", time.Second, 1950553118 * time.Nanosecond, 1950553118 * time.Nanosecond, true},
		{"fractional milliseconds preserved", "2.5ms", time.Nanosecond, 2500 * time.Microsecond, 2500 * time.Microsecond, true},
		{"local greater than API", "2s", 10 * time.Second, 7 * time.Second, 13 * time.Second, true},
		{"local jitter dips below API", "2s", 2 * time.Second, 2 * time.Second, 2600 * time.Millisecond, true},
		{"local clamp", "", time.Minute, maxDelay, maxDelay, false},
		{"default is not explicit", "", time.Second, 700 * time.Millisecond, 1300 * time.Millisecond, false},
		{"invalid retry delay", "bad", time.Second, 700 * time.Millisecond, 1300 * time.Millisecond, false},
		{"negative retry delay", "-2s", time.Second, 700 * time.Millisecond, 1300 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"error":{"details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":%q}]}}`, tc.retryDelay)
			se := classifyError(429, []byte(body))
			if se.explicitDelay != tc.explicit {
				t.Fatalf("explicitDelay = %v", se.explicitDelay)
			}
			for i := 0; i < 100; i++ {
				wait := retryWait(tc.local, se)
				if wait < tc.min || wait > tc.max {
					t.Fatalf("wait = %v, want [%v, %v]", wait, tc.min, tc.max)
				}
			}
		})
	}
}

func TestGetString(t *testing.T) {
	tests := []struct {
		name string
		m    map[string]any
		key  string
		want string
	}{
		{
			name: "key exists with string value",
			m:    map[string]any{"title": "hello"},
			key:  "title",
			want: "hello",
		},
		{
			name: "key missing",
			m:    map[string]any{"other": "value"},
			key:  "title",
			want: "",
		},
		{
			name: "key exists with wrong type (int)",
			m:    map[string]any{"title": 42},
			key:  "title",
			want: "",
		},
		{
			name: "key exists with wrong type (bool)",
			m:    map[string]any{"title": true},
			key:  "title",
			want: "",
		},
		{
			name: "nil map",
			m:    nil,
			key:  "title",
			want: "",
		},
		{
			name: "empty map",
			m:    map[string]any{},
			key:  "title",
			want: "",
		},
		{
			name: "empty string value",
			m:    map[string]any{"title": ""},
			key:  "title",
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := getString(tc.m, tc.key)
			if got != tc.want {
				t.Errorf("getString(%v, %q) = %q, want %q", tc.m, tc.key, got, tc.want)
			}
		})
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
			expiryDate: now + 30000, // 30s from now, but 60s buffer means expired
			want:       true,
		},
		{
			name:       "token valid just outside buffer",
			expiryDate: now + 65000,
			want:       false,
		},
		{
			name:       "token valid with plenty of time",
			expiryDate: now + 3600000, // 1 hour from now
			want:       false,
		},
		{
			name:       "token with zero expiry date",
			expiryDate: 0,
			want:       true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &oauthCreds{ExpiryDate: tc.expiryDate}
			got := isExpired(c)
			if got != tc.want {
				t.Errorf("isExpired(expiryDate=%d) = %v, want %v (now=%d)", tc.expiryDate, got, tc.want, now)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// credsFiles
// ---------------------------------------------------------------------------

func TestCredsFiles(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	paths := credsFiles()

	if len(paths) != 2 {
		t.Fatalf("credsFiles() returned %d paths, want 2", len(paths))
	}

	if !strings.HasSuffix(paths[0], filepath.Join(".gsearch", "oauth_creds.json")) {
		t.Errorf("first path should end with .gsearch/oauth_creds.json, got %q", paths[0])
	}
	if !strings.HasSuffix(paths[1], filepath.Join(".gemini", "oauth_creds.json")) {
		t.Errorf("second path should end with .gemini/oauth_creds.json, got %q", paths[1])
	}

	// Both paths should be absolute
	for i, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("credsFiles()[%d] = %q is not absolute", i, p)
		}
	}
}

// ---------------------------------------------------------------------------
// loadCreds — uses temp files to avoid touching real credentials
// ---------------------------------------------------------------------------

func TestLoadCreds(t *testing.T) {
	t.Run("reads first available creds file", func(t *testing.T) {
		tmp := t.TempDir()

		// Override HOME so credsFiles() resolves to temp dir
		t.Setenv("HOME", tmp)

		gsearchDir := filepath.Join(tmp, ".gsearch")
		if err := os.MkdirAll(gsearchDir, 0755); err != nil {
			t.Fatal(err)
		}

		creds := oauthCreds{
			AccessToken:  "tok-abc",
			RefreshToken: "ref-123",
			ExpiryDate:   time.Now().UnixMilli() + 3600000,
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		if err := os.WriteFile(filepath.Join(gsearchDir, "oauth_creds.json"), data, 0600); err != nil {
			t.Fatal(err)
		}

		got, path, err := loadCreds()
		if err != nil {
			t.Fatalf("loadCreds() error: %v", err)
		}
		if got.AccessToken != "tok-abc" {
			t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok-abc")
		}
		if !strings.Contains(path, ".gsearch") {
			t.Errorf("path = %q, expected it to contain .gsearch", path)
		}
	})

	t.Run("falls back to gemini creds", func(t *testing.T) {
		tmp := t.TempDir()

		t.Setenv("HOME", tmp)

		geminiDir := filepath.Join(tmp, ".gemini")
		if err := os.MkdirAll(geminiDir, 0755); err != nil {
			t.Fatal(err)
		}

		creds := oauthCreds{
			AccessToken:  "gemini-tok",
			RefreshToken: "gemini-ref",
			ExpiryDate:   time.Now().UnixMilli() + 3600000,
		}
		data, _ := json.MarshalIndent(creds, "", "  ")
		if err := os.WriteFile(filepath.Join(geminiDir, "oauth_creds.json"), data, 0600); err != nil {
			t.Fatal(err)
		}

		got, path, err := loadCreds()
		if err != nil {
			t.Fatalf("loadCreds() error: %v", err)
		}
		if got.AccessToken != "gemini-tok" {
			t.Errorf("AccessToken = %q, want %q", got.AccessToken, "gemini-tok")
		}
		if !strings.Contains(path, ".gemini") {
			t.Errorf("path = %q, expected it to contain .gemini", path)
		}
	})

	t.Run("returns error when no creds exist", func(t *testing.T) {
		tmp := t.TempDir()

		t.Setenv("HOME", tmp)

		_, _, err := loadCreds()
		if err == nil {
			t.Fatal("expected error when no creds files exist")
		}
		if !strings.Contains(err.Error(), "no OAuth credentials found") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("skips invalid JSON", func(t *testing.T) {
		tmp := t.TempDir()

		t.Setenv("HOME", tmp)

		gsearchDir := filepath.Join(tmp, ".gsearch")
		if err := os.MkdirAll(gsearchDir, 0755); err != nil {
			t.Fatal(err)
		}
		// Write invalid JSON to gsearch
		os.WriteFile(filepath.Join(gsearchDir, "oauth_creds.json"), []byte("{bad json}"), 0600)

		// Write valid JSON to gemini
		geminiDir := filepath.Join(tmp, ".gemini")
		if err := os.MkdirAll(geminiDir, 0755); err != nil {
			t.Fatal(err)
		}
		creds := oauthCreds{AccessToken: "fallback-tok"}
		data, _ := json.MarshalIndent(creds, "", "  ")
		os.WriteFile(filepath.Join(geminiDir, "oauth_creds.json"), data, 0600)

		got, _, err := loadCreds()
		if err != nil {
			t.Fatalf("loadCreds() error: %v", err)
		}
		if got.AccessToken != "fallback-tok" {
			t.Errorf("AccessToken = %q, want %q", got.AccessToken, "fallback-tok")
		}
	})
}

// ---------------------------------------------------------------------------
// saveCreds
// ---------------------------------------------------------------------------

func TestSaveCredsTightensExistingPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth_creds.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := saveCreds(path, &oauthCreds{AccessToken: "fake-renewed"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Fatalf("permissions = %o, want 600", perm)
	}
}

func TestSaveCreds(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "oauth_creds.json")

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

	// Check file permissions
	info, _ := os.Stat(path)
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions = %o, want 0600", perm)
	}
}

// ---------------------------------------------------------------------------
// parseResponse
// ---------------------------------------------------------------------------

func TestParseResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	t.Run("full response with candidates and grounding", func(t *testing.T) {
		resp := map[string]any{
			"response": map[string]any{
				"candidates": []any{
					map[string]any{
						"content": map[string]any{
							"parts": []any{
								map[string]any{"text": "Go is a programming language."},
							},
						},
						"groundingMetadata": map[string]any{
							"groundingChunks": []any{
								map[string]any{
									"web": map[string]any{
										"title": "Go Website",
										"uri":   srv.URL + "/go",
									},
								},
								map[string]any{
									"web": map[string]any{
										"title": "Wikipedia",
										"uri":   srv.URL + "/wiki/Go",
									},
								},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}

		if !strings.Contains(text, "Go is a programming language.") {
			t.Errorf("missing main text in response: %q", text)
		}
		if !strings.Contains(text, "Sources:") {
			t.Errorf("missing Sources section: %q", text)
		}
		if !strings.Contains(text, "[1] [Go Website]("+srv.URL+"/go)") {
			t.Errorf("missing source 1: %q", text)
		}
		if !strings.Contains(text, "[2] [Wikipedia]("+srv.URL+"/wiki/Go)") {
			t.Errorf("missing source 2: %q", text)
		}
	})

	t.Run("empty candidates returns No results", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if text != "No results" {
			t.Errorf("parseResponse() = %q, want %q", text, "No results")
		}
	})

	t.Run("missing candidates field returns No results", func(t *testing.T) {
		resp := map[string]any{
			"response": map[string]any{
				"something": "else",
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if text != "No results" {
			t.Errorf("parseResponse() = %q, want %q", text, "No results")
		}
	})

	t.Run("response without wrapper (flat candidates)", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "flat response"},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if !strings.Contains(text, "flat response") {
			t.Errorf("expected 'flat response' in output, got: %q", text)
		}
	})

	t.Run("multiple parts concatenated", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "Hello "},
							map[string]any{"text": "World"},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if !strings.Contains(text, "Hello World") {
			t.Errorf("expected concatenated text, got: %q", text)
		}
	})

	t.Run("citation insertion with groundingSupports", func(t *testing.T) {
		// "Hello World" = 11 bytes, insert [1] at position 5 ("Hello")
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "Hello World"},
						},
					},
					"groundingMetadata": map[string]any{
						"groundingChunks": []any{
							map[string]any{
								"web": map[string]any{
									"title": "Source1",
									"uri":   srv.URL + "/source",
								},
							},
						},
						"groundingSupports": []any{
							map[string]any{
								"segment": map[string]any{
									"endIndex": float64(5),
								},
								"groundingChunkIndices": []any{float64(0)},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if !strings.Contains(text, "Hello[1] World") {
			t.Errorf("expected citation inserted, got: %q", text)
		}
	})

	t.Run("citation with endIndex beyond text length", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "Hi"},
						},
					},
					"groundingMetadata": map[string]any{
						"groundingChunks": []any{
							map[string]any{
								"web": map[string]any{
									"title": "Src",
									"uri":   srv.URL + "/source",
								},
							},
						},
						"groundingSupports": []any{
							map[string]any{
								"segment": map[string]any{
									"endIndex": float64(999),
								},
								"groundingChunkIndices": []any{float64(0)},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		// Citation should be clamped to end of text
		if !strings.Contains(text, "Hi[1]") {
			t.Errorf("expected citation clamped to end, got: %q", text)
		}
	})

	t.Run("multiple citations from different chunks", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "ABCDEFGHIJ"},
						},
					},
					"groundingMetadata": map[string]any{
						"groundingChunks": []any{
							map[string]any{"web": map[string]any{"title": "S1", "uri": srv.URL + "/one"}},
							map[string]any{"web": map[string]any{"title": "S2", "uri": srv.URL + "/two"}},
						},
						"groundingSupports": []any{
							map[string]any{
								"segment":               map[string]any{"endIndex": float64(3)},
								"groundingChunkIndices": []any{float64(0)},
							},
							map[string]any{
								"segment":               map[string]any{"endIndex": float64(7)},
								"groundingChunkIndices": []any{float64(1)},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		// Should have [1] after ABC and [2] after ABCDEFG
		if !strings.Contains(text, "ABC[1]") {
			t.Errorf("expected [1] citation, got: %q", text)
		}
		if !strings.Contains(text, "[2]") {
			t.Errorf("expected [2] citation, got: %q", text)
		}
	})

	t.Run("support referencing multiple chunks", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "ABCDE"},
						},
					},
					"groundingMetadata": map[string]any{
						"groundingChunks": []any{
							map[string]any{"web": map[string]any{"title": "S1", "uri": srv.URL + "/one"}},
							map[string]any{"web": map[string]any{"title": "S2", "uri": srv.URL + "/two"}},
						},
						"groundingSupports": []any{
							map[string]any{
								"segment":               map[string]any{"endIndex": float64(5)},
								"groundingChunkIndices": []any{float64(0), float64(1)},
							},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if !strings.Contains(text, "ABCDE[1][2]") {
			t.Errorf("expected multi-citation [1][2], got: %q", text)
		}
	})

	t.Run("no grounding metadata", func(t *testing.T) {
		resp := map[string]any{
			"candidates": []any{
				map[string]any{
					"content": map[string]any{
						"parts": []any{
							map[string]any{"text": "plain answer"},
						},
					},
				},
			},
		}
		data, _ := json.Marshal(resp)

		text, err := parseResponse(data)
		if err != nil {
			t.Fatalf("parseResponse() error: %v", err)
		}
		if text != "plain answer" {
			t.Errorf("expected plain text, got: %q", text)
		}
		if strings.Contains(text, "Sources:") {
			t.Error("should not have Sources section without grounding")
		}
	})

	t.Run("malformed JSON returns error", func(t *testing.T) {
		text, err := parseResponse([]byte("{invalid"))
		checkResult(t, text, err, "", "decode search response")
	})
}

// ---------------------------------------------------------------------------
// loadProject — mock HTTP
// ---------------------------------------------------------------------------

func TestSourceURLResolution(t *testing.T) {
	isolateServer(t)
	requests := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		requests++
		return testResponse(http.StatusNoContent, "", false), nil
	})

	t.Run("external destination is not contacted", func(t *testing.T) {
		resolved := resolveRedirects([]string{"https://example.test/source"})
		if len(resolved) != 1 || resolved[0] != "https://example.test/source" {
			t.Fatalf("resolved = %v", resolved)
		}
		if requests != 0 {
			t.Fatalf("external requests = %d, want 0", requests)
		}
	})

	t.Run("malformed URI becomes No URI", func(t *testing.T) {
		payload := `{"candidates":[{"content":{"parts":[{"text":"answer"}]},"groundingMetadata":{"groundingChunks":[{"web":{"title":"Broken","uri":"http://["}}]}}]}`
		text, err := parseResponse([]byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text, "[Broken](No URI)") {
			t.Fatalf("text = %q", text)
		}
		if requests != 0 {
			t.Fatalf("requests = %d, want 0", requests)
		}
	})
}

func TestLoadConfigProject(t *testing.T) {
	isolateServer(t)
	dir := filepath.Join(os.Getenv("HOME"), ".gsearch")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"auth_type":"oauth","project":"saved-project"}`), 0600); err != nil {
		t.Fatal(err)
	}
	loadConfig()
	if configuredProject != "saved-project" {
		t.Fatalf("configuredProject = %q, want saved-project", configuredProject)
	}
}

func TestLoadProject(t *testing.T) {
	for _, env := range []string{"GSEARCH_PROJECT", "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_PROJECT_ID"} {
		t.Run(env, func(t *testing.T) {
			isolateServer(t)
			t.Setenv(env, "fake-env-project")
			got, err := loadProject("fake-token")
			if err != nil || got != "fake-env-project" {
				t.Fatalf("loadProject() = %q, %v", got, err)
			}
		})
	}
	t.Run("saved config project", func(t *testing.T) {
		isolateServer(t)
		configuredProject = "saved-project"
		got, err := loadProject("fake-token")
		if err != nil || got != "saved-project" {
			t.Fatalf("loadProject() = %q, %v", got, err)
		}
	})
	t.Run("environment overrides saved project", func(t *testing.T) {
		isolateServer(t)
		configuredProject = "saved-project"
		t.Setenv("GSEARCH_PROJECT", "env-project")
		got, err := loadProject("fake-token")
		if err != nil || got != "env-project" {
			t.Fatalf("loadProject() = %q, %v", got, err)
		}
	})
	for _, tc := range []struct {
		name, body, want, wantErr string
		status                    int
		readError                 bool
	}{
		{"provisioned", `{"cloudaicompanionProject":"fake-project"}`, "fake-project", "", 200, false},
		{"malformed", `{invalid`, "", "decode loadCodeAssist", 200, false},
		{"status", `{}`, "", "loadCodeAssist 403", 403, false},
		{"read error", `{}`, "", "fake read error", 200, true},
		{"API error", `{"error":{"code":7,"message":"denied"}}`, "", "API error 7: denied", 200, false},
		{"validation", `{"ineligibleTiers":[{"reasonCode":"VALIDATION_REQUIRED","reasonMessage":"verify","validationUrl":"https://verify.invalid"}]}`, "", "account needs verification", 200, false},
		{"no tier", `{}`, "", "no eligible tier", 200, false},
		{"requires project", `{"allowedTiers":[{"id":"paid","isDefault":true,"userDefinedCloudaicompanionProject":true}]}`, "", "requires GSEARCH_PROJECT", 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				checkRequest(t, req, "POST", oauthEndpoint+":loadCodeAssist", "fake-token")
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				metadata, _ := body["metadata"].(map[string]any)
				if body["cloudaicompanionProject"] != "" || metadata["pluginType"] != "GEMINI" {
					t.Fatalf("unexpected body: %v", body)
				}
				return testResponse(tc.status, tc.body, tc.readError), nil
			})
			got, err := loadProject("fake-token")
			checkResult(t, got, err, tc.want, tc.wantErr)
			if calls != 1 {
				t.Fatalf("requests = %d, want 1", calls)
			}
		})
	}
	t.Run("onboarding and polling", func(t *testing.T) {
		isolateServer(t)
		calls := 0
		mockTransport(t, func(req *http.Request) (*http.Response, error) {
			calls++
			switch calls {
			case 1:
				checkRequest(t, req, "POST", oauthEndpoint+":loadCodeAssist", "fake-token")
				return testResponse(200, `{"allowedTiers":[{"id":"other"},{"id":"free","isDefault":true}]}`, false), nil
			case 2:
				checkRequest(t, req, "POST", oauthEndpoint+":onboardUser", "fake-token")
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["tierId"] != "free" {
					t.Fatalf("tier = %v", body["tierId"])
				}
				return testResponse(200, `{"name":"operations/fake"}`, false), nil
			case 3:
				checkRequest(t, req, "GET", oauthEndpoint+"/operations/fake", "fake-token")
				return testResponse(200, `{"done":true,"response":{"cloudaicompanionProject":{"id":"fake-project"}}}`, false), nil
			default:
				t.Fatalf("unexpected request: %s", req.URL)
				return nil, errors.New("unexpected request")
			}
		})
		got, err := loadProject("fake-token")
		checkResult(t, got, err, "fake-project", "")
		if calls != 3 {
			t.Fatalf("requests = %d, want 3", calls)
		}
	})
}

// ---------------------------------------------------------------------------
// doSearch — mock HTTP server
// ---------------------------------------------------------------------------

func TestDoSearch(t *testing.T) {
	for _, mode := range []string{"OAuth", "API key"} {
		t.Run(mode, func(t *testing.T) {
			isolateServer(t)
			if mode == "API key" {
				apiKey = "fake-api-key"
			}
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				token, endpoint := "fake-token", oauthEndpoint+":generateContent"
				if apiKey != "" {
					token, endpoint = "", apiKeyEndpoint+"/models/"+defaultModel+":generateContent"
				}
				checkRequest(t, req, "POST", endpoint, token)
				if req.Header.Get("Content-Type") != "application/json" || req.Header.Get("Accept") != "application/json" || req.Header.Get("User-Agent") != geminiUserAgent(defaultModel) {
					t.Fatalf("unexpected headers: %v", req.Header)
				}
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if apiKey == "" {
					if body["model"] != defaultModel || body["project"] != "fake-project" || getString(body, "user_prompt_id") == "" {
						t.Fatalf("unexpected wrapper: %v", body)
					}
					body, _ = body["request"].(map[string]any)
					if body["session_id"] != "fake-session" {
						t.Fatalf("session = %v", body["session_id"])
					}
				} else if _, ok := body["request"]; ok {
					t.Fatal("API key request must not be wrapped")
				}
				contents, _ := json.Marshal(body["contents"])
				if string(contents) != `[{"parts":[{"text":"fake query"}],"role":"user"}]` {
					t.Fatalf("contents = %s", contents)
				}
				tools, _ := json.Marshal(body["tools"])
				if string(tools) != `[{"googleSearch":{}}]` {
					t.Fatalf("tools = %s", tools)
				}
				config, _ := body["generationConfig"].(map[string]any)
				if config["temperature"] != float64(0) || config["topP"] != float64(1) || body["systemInstruction"] == nil {
					t.Fatalf("unexpected config: %v", body)
				}
				response := `{"candidates":[{"content":{"parts":[{"text":"search result"}]}}]}`
				if apiKey == "" {
					response = `{"response":` + response + `}`
				}
				return testResponse(200, response, false), nil
			})
			text, status, _, err := doSearch(context.Background(), "fake query", defaultModel, "fake-token", "fake-project")
			checkResult(t, text, err, "search result", "")
			if status != 200 || calls != 1 {
				t.Fatalf("status = %d, calls = %d", status, calls)
			}
		})
	}
	for _, tc := range []struct {
		name, body, wantErr string
		status, kind        int
		readError           bool
	}{
		{"rate limit", `{}`, "rate limited", 429, errRetryable, false},
		{"server error", `{}`, "API 500", 500, errRetryable, false},
		{"malformed", `{invalid`, "decode search response", 200, 0, false},
		{"API error", `{"error":{"code":7,"message":"denied"}}`, "API error 7: denied", 200, 0, false},
		{"wrapped API error", `{"response":{"error":{"code":7,"message":"denied"}}}`, "API error 7: denied", 200, 0, false},
		{"read error", `{}`, "fake read error", 0, errRetryable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				return testResponse(tc.status, tc.body, tc.readError), nil
			})
			text, status, se, err := doSearch(context.Background(), "fake query", defaultModel, "fake-token", "fake-project")
			checkResult(t, text, err, "", tc.wantErr)
			if status != tc.status || se.kind != tc.kind || calls != 1 {
				t.Fatalf("status = %d, kind = %d, calls = %d", status, se.kind, calls)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// searchHandler — MCP handler
// ---------------------------------------------------------------------------

func TestSearchHandler(t *testing.T) {
	isolateServer(t)
	t.Run("missing query parameter", func(t *testing.T) {
		req := mcp.CallToolRequest{}
		req.Params.Name = "google_search"
		req.Params.Arguments = map[string]any{}

		result, err := searchHandler(context.Background(), req)
		if err != nil {
			t.Fatalf("searchHandler() error: %v", err)
		}
		// Result should be an error response
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if !result.IsError {
			t.Error("expected IsError=true for missing query")
		}
		// Check that the error text mentions "query"
		if len(result.Content) == 0 {
			t.Fatal("expected content in error result")
		}
		textContent, ok := result.Content[0].(mcp.TextContent)
		if !ok {
			t.Fatal("expected TextContent")
		}
		if !strings.Contains(textContent.Text, "query") {
			t.Errorf("error text should mention 'query', got: %q", textContent.Text)
		}
	})

	t.Run("valid query parameter structure", func(t *testing.T) {
		req := mcp.CallToolRequest{}
		req.Params.Name = "google_search"
		req.Params.Arguments = map[string]any{
			"query": "test search query",
		}

		result, err := searchHandler(context.Background(), req)
		if err != nil {
			t.Fatalf("searchHandler() unexpected Go error: %v", err)
		}
		if result == nil || !result.IsError {
			t.Fatal("expected MCP error without fake credentials")
		}
		if len(result.Content) > 0 {
			textContent, ok := result.Content[0].(mcp.TextContent)
			if ok && !strings.Contains(textContent.Text, "search error") {
				t.Errorf("expected 'search error' prefix, got: %q", textContent.Text)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// truncate
// ---------------------------------------------------------------------------

func TestTruncate(t *testing.T) {
	tests := []struct {
		name string
		s    string
		n    int
		want string
	}{
		{"empty string", "", 10, ""},
		{"shorter than limit", "hello", 10, "hello"},
		{"exact limit", "hello", 5, "hello"},
		{"longer than limit", "hello world", 5, "hello..."},
		{"limit zero", "hello", 0, "..."},
		{"unicode truncates bytes", "café☕test", 10, "café☕te..."},
		{"single char", "x", 1, "x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncate(tt.s, tt.n)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.n, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// classifyError
// ---------------------------------------------------------------------------

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantKind int
		wantMin  time.Duration
		wantMax  time.Duration
	}{
		{
			"429 with RATE_LIMIT_EXCEEDED is retryable",
			429,
			`{"error":{"code":429,"message":"quota exceeded","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"RATE_LIMIT_EXCEEDED","domain":"cloudcode-pa.googleapis.com"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"1.950553118s"}]}}`,
			errRetryable, 1950 * time.Millisecond, 1951 * time.Millisecond,
		},
		{
			"429 with QUOTA_EXHAUSTED is terminal",
			429,
			`{"error":{"code":429,"message":"quota exhausted","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"QUOTA_EXHAUSTED","domain":"cloudcode-pa.googleapis.com"}]}}`,
			errTerminal, 0, 30 * time.Second,
		},
		{
			"429 with PerDay quota is terminal",
			429,
			`{"error":{"code":429,"message":"daily limit","details":[{"@type":"type.googleapis.com/google.rpc.QuotaFailure","violations":[{"quotaId":"GenerateContentRequestsPerDay"}]}]}}`,
			errTerminal, 0, 30 * time.Second,
		},
		{
			"429 with long retryDelay (>5min) is terminal",
			429,
			`{"error":{"code":429,"details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"600s"}]}}`,
			errTerminal, 600 * time.Second, 600 * time.Second,
		},
		{
			"403 is fatal",
			403,
			`{"error":{"message":"forbidden"}}`,
			errFatal, 0, 0,
		},
		{
			"429 QUOTA_EXHAUSTED with RetryInfo preserves delay",
			429,
			`{"error":{"code":429,"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"QUOTA_EXHAUSTED"},{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"45s"}]}}`,
			errTerminal, 45 * time.Second, 45 * time.Second,
		},
		{
			"429 with short retryDelay is retryable",
			429,
			`{"error":{"details":[{"@type":"type.googleapis.com/google.rpc.RetryInfo","retryDelay":"2s"}]}}`,
			errRetryable, 2 * time.Second, 2 * time.Second,
		},
		{
			"400 is fatal",
			400,
			`{"error":{"message":"bad request"}}`,
			errFatal, 0, 0,
		},
		{
			"404 is terminal (model not found)",
			404,
			`{"error":{"message":"not found"}}`,
			errTerminal, 0, 0,
		},
		{
			"503 is terminal (switch model)",
			503,
			`{"error":{"message":"service unavailable"}}`,
			errTerminal, 0, 30 * time.Second,
		},
		{
			"malformed JSON defaults to retryable",
			429,
			`not json`,
			errRetryable, defaultRetryDelay, defaultRetryDelay,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			se := classifyError(tt.status, []byte(tt.body))
			if se.kind != tt.wantKind {
				t.Errorf("classifyError() kind = %d, want %d", se.kind, tt.wantKind)
			}
			if tt.wantMin > 0 && (se.delay < tt.wantMin || se.delay > tt.wantMax) {
				t.Errorf("classifyError() delay = %v, want between %v and %v", se.delay, tt.wantMin, tt.wantMax)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// provider antigravity
// ---------------------------------------------------------------------------

func TestAgyUserAgentFor(t *testing.T) {
	for _, tc := range []struct{ goos, goarch, want string }{
		{"darwin", "arm64", "antigravity/cli/1.4.6 (aidev_client; os_type=darwin; arch=arm64; cl=1005129088; auth_method=consumer)"},
		{"windows", "amd64", "antigravity/cli/1.4.6 (aidev_client; os_type=windows; arch=amd64; cl=1005129088; auth_method=consumer)"},
		{"linux", "386", "antigravity/cli/1.4.6 (aidev_client; os_type=linux; arch=amd64; cl=1005129088; auth_method=consumer)"},
	} {
		if got := agyUserAgentFor(tc.goos, tc.goarch); got != tc.want {
			t.Errorf("agyUserAgentFor(%s, %s) = %q, want %q", tc.goos, tc.goarch, got, tc.want)
		}
	}
}

func TestAgyEndpoint(t *testing.T) {
	isolateServer(t)
	if got := agyEndpoint(); got != agyDailyEndpoint {
		t.Errorf("agyEndpoint() = %q, want daily default", got)
	}
	for _, value := range []string{"prod", "PROD", " prod "} {
		t.Setenv("GSEARCH_ANTIGRAVITY_HOST", value)
		if got := agyEndpoint(); got != agyProdEndpoint {
			t.Errorf("agyEndpoint() with %q = %q, want prod", value, got)
		}
	}
}

func TestRefreshTokenAntigravity(t *testing.T) {
	isolateServer(t)
	creds := agyCreds(t, "fake-old")
	calls := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if err := req.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if req.PostForm.Get("client_id") != agyClientID || req.PostForm.Get("client_secret") != agyClientSecret {
			t.Fatalf("refresh form uses wrong client: %v", req.PostForm)
		}
		return testResponse(200, `{"access_token":"fake-agy-new","expires_in":3600}`, false), nil
	})
	if err := refreshToken(creds); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || creds.AccessToken != "fake-agy-new" || creds.RefreshToken != "fake-agy-refresh" || creds.Provider != "antigravity" {
		t.Fatalf("unexpected creds after refresh: %+v (calls=%d)", creds, calls)
	}
	reloaded, _, err := loadCreds()
	if err != nil || reloaded.Provider != "antigravity" {
		t.Fatalf("provider not persisted: %+v %v", reloaded, err)
	}
}

func TestLoadProjectAntigravity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		body         string
		status       int
		prod         bool
		want         string
		wantErr      string
		wantStatusEr bool
	}{
		{"provisioned daily", `{"cloudaicompanionProject":"agy-project"}`, 200, false, "agy-project", "", false},
		{"provisioned prod", `{"cloudaicompanionProject":"agy-project"}`, 200, true, "agy-project", "", false},
		{"requires project", `{"allowedTiers":[{"id":"standard-tier","isDefault":true,"userDefinedCloudaicompanionProject":true}]}`, 200, false, "", "requires GSEARCH_PROJECT", false},
		{"401 typed", `{"error":{"message":"revoked"}}`, 401, false, "", "loadCodeAssist 401", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			agyCreds(t, "fake-agy-token")
			if tc.prod {
				t.Setenv("GSEARCH_ANTIGRAVITY_HOST", "prod")
			}
			wantEndpoint := agyDailyEndpoint
			if tc.prod {
				wantEndpoint = agyProdEndpoint
			}
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				checkAgyHeaders(t, req, "fake-agy-token")
				if req.Method != "POST" || req.URL.String() != wantEndpoint+":loadCodeAssist" {
					t.Fatalf("request = %s %s", req.Method, req.URL)
				}
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				metadata, _ := body["metadata"].(map[string]any)
				if len(body) != 1 || len(metadata) != 1 || metadata["ideType"] != "ANTIGRAVITY" {
					t.Fatalf("unexpected antigravity loadCodeAssist body: %v", body)
				}
				return testResponse(tc.status, tc.body, false), nil
			})
			got, err := loadProject("fake-agy-token")
			checkResult(t, got, err, tc.want, tc.wantErr)
			if tc.wantStatusEr {
				var se searchError
				if !errors.As(err, &se) || se.status != 401 {
					t.Fatalf("expected typed 401, got %v", err)
				}
			}
			if calls != 1 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}

func TestOnboardAntigravityDoneImmediately(t *testing.T) {
	isolateServer(t)
	agyCreds(t, "fake-agy-token")
	calls := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Method != "POST" || req.URL.String() != agyDailyEndpoint+":onboardUser" {
			t.Fatalf("request = %s %s", req.Method, req.URL)
		}
		return testResponse(200, `{"done":true,"response":{"cloudaicompanionProject":{"id":"instant-project"}}}`, false), nil
	})
	got, err := onboardUser("fake-agy-token", "free-tier", "")
	checkResult(t, got, err, "instant-project", "")
	if calls != 1 {
		t.Fatalf("requests = %d, want 1 (no polling when already done)", calls)
	}
}

func TestOnboardAntigravity(t *testing.T) {
	isolateServer(t)
	agyCreds(t, "fake-agy-token")
	calls := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		calls++
		checkAgyHeaders(t, req, "fake-agy-token")
		switch calls {
		case 1:
			if req.URL.String() != agyDailyEndpoint+":onboardUser" {
				t.Fatalf("url = %s", req.URL)
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			metadata, _ := body["metadata"].(map[string]any)
			if body["tierId"] != "free-tier" || len(metadata) != 1 || metadata["ideType"] != "ANTIGRAVITY" || body["cloudaicompanionProject"] != nil {
				t.Fatalf("unexpected antigravity onboard body: %v", body)
			}
			return testResponse(200, `{"name":"operations/agy-op"}`, false), nil
		default:
			if req.Method != "GET" || req.URL.String() != agyDailyEndpoint+"/operations/agy-op" {
				t.Fatalf("poll request = %s %s", req.Method, req.URL)
			}
			return testResponse(200, `{"done":true,"response":{"cloudaicompanionProject":{"id":"agy-onboard"}}}`, false), nil
		}
	})
	got, err := onboardUser("fake-agy-token", "free-tier", "must-not-leak")
	checkResult(t, got, err, "agy-onboard", "")
	if calls != 2 {
		t.Fatalf("requests = %d", calls)
	}
}

func TestDoSearchAntigravity(t *testing.T) {
	isolateServer(t)
	agyCreds(t, "fake-agy-token")
	calls := 0
	mockTransport(t, func(req *http.Request) (*http.Response, error) {
		calls++
		checkAgyHeaders(t, req, "fake-agy-token")
		if req.Method != "POST" || req.URL.String() != agyDailyEndpoint+":generateContent" {
			t.Fatalf("request = %s %s", req.Method, req.URL)
		}
		var body map[string]any
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		wantJSON := `{
			"project":"agy-project",
			"request":{
				"contents":[{"role":"user","parts":[{"text":"fake query"}]}],
				"systemInstruction":{"role":"user","parts":[{"text":"` + agySearchSystemInstruction + `"}]},
				"tools":[{"googleSearch":{"enhancedContent":{"imageSearch":{"maxResultCount":5}}}}],
				"generationConfig":{"candidateCount":1}
			},
			"model":"` + agyDefaultModel + `",
			"userAgent":"antigravity",
			"requestType":"web_search"
		}`
		var want map[string]any
		if err := json.Unmarshal([]byte(wantJSON), &want); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(body, want) {
			gotJSON, _ := json.Marshal(body)
			wantJSON, _ := json.Marshal(want)
			t.Fatalf("antigravity request differs from captured contract\ngot:  %s\nwant: %s", gotJSON, wantJSON)
		}
		return testResponse(200, `{"candidates":[{"content":{"parts":[{"text":"agy grounded answer"}]}}]}`, false), nil
	})
	text, status, _, err := doSearch(context.Background(), "fake query", agyDefaultModel, "fake-agy-token", "agy-project")
	checkResult(t, text, err, "agy grounded answer", "")
	if status != 200 || calls != 1 {
		t.Fatalf("status = %d, calls = %d", status, calls)
	}
}

func TestGoogleSearchAntigravityModels(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured bool
		wantModel  string
	}{
		{"default agy models", false, agyDefaultModel},
		{"user configured model wins", true, "custom-model"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolateServer(t)
			agyCreds(t, "fake-agy-token")
			cachedProject = "agy-project"
			modelsConfigured = tc.configured
			if tc.configured {
				models = []string{"custom-model"}
			}
			calls := 0
			mockTransport(t, func(req *http.Request) (*http.Response, error) {
				calls++
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
				if body["model"] != tc.wantModel {
					t.Fatalf("model = %v, want %q", body["model"], tc.wantModel)
				}
				return testResponse(200, `{"candidates":[{"content":{"parts":[{"text":"ok"}]}}]}`, false), nil
			})
			got, err := googleSearch(context.Background(), "fake query")
			checkResult(t, got, err, "ok", "")
			if calls != 1 {
				t.Fatalf("requests = %d", calls)
			}
		})
	}
}
