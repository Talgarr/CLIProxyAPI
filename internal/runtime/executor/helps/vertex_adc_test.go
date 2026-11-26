package helps

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestVertexADCTokensCacheRefreshAndCredentialRotation(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" {
			t.Error("expected refresh-token exchange")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":3600}`, calls.Add(1))
	}))
	defer server.Close()

	auth := &cliproxyauth.Auth{
		ID: "vertex-adc",
		Metadata: map[string]any{
			"adc": map[string]any{
				"type":          "authorized_user",
				"client_id":     "fixture",
				"client_secret": "fixture",
				"refresh_token": "refresh-1",
				"token_uri":     server.URL,
			},
		},
	}

	var cache VertexADCTokenCache
	ctx, cancel := context.WithCancel(context.Background())
	token, err := cache.Token(ctx, &config.Config{}, auth)
	cancel()
	if err != nil || token != "token-1" {
		t.Fatal("initial acquisition failed", err)
	}

	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			if tok, errTok := cache.Token(context.Background(), &config.Config{}, auth); errTok != nil || tok != "token-1" {
				t.Error("concurrent cached token failed", errTok)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal("concurrent requests did not reuse the access token")
	}

	for _, entry := range cache.entries {
		entry.token.Expiry = time.Now().Add(-time.Hour)
	}
	if tok, errTok := cache.Token(context.Background(), &config.Config{}, auth); errTok != nil || tok != "token-2" {
		t.Fatal("expired token did not refresh with a fresh context", errTok)
	}

	rotated := auth.Clone()
	rotated.Metadata["adc"].(map[string]any)["refresh_token"] = "refresh-2"
	if tok, errTok := cache.Token(context.Background(), &config.Config{}, rotated); errTok != nil || tok != "token-3" {
		t.Fatal("rotated credential reused an old token", errTok)
	}
}

func TestVertexADCTokenFailureWithholdsProviderBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "secret provider error")
	}))
	defer server.Close()

	auth := &cliproxyauth.Auth{
		Metadata: map[string]any{
			"adc": map[string]any{
				"type":      "authorized_user",
				"token_uri": server.URL,
			},
		},
	}
	var cache VertexADCTokenCache
	if _, err := cache.Token(context.Background(), nil, auth); err == nil || err.Error() != "vertex ADC: token acquisition failed" {
		t.Fatal("provider error was not sanitized", err)
	}
}

func TestVertexADCQuotaAuthRespectsExplicitCustomHeader(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Attributes: map[string]string{
			"header:x-goog-user-project": "override-project",
		},
		Metadata: map[string]any{
			"adc": map[string]any{
				"type":             "authorized_user",
				"quota_project_id": "adc-quota-project",
			},
		},
	}

	cloned := VertexADCQuotaAuth(auth)
	if got := cloned.Attributes["header:x-goog-user-project"]; got != "override-project" {
		t.Fatalf("explicit custom quota header = %q, want %q", got, "override-project")
	}
	if _, duplicated := cloned.Attributes["header:X-Goog-User-Project"]; duplicated {
		t.Fatal("VertexADCQuotaAuth duplicated an existing case-insensitive quota header")
	}
}
