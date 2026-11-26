package auth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestVertexADCLoginPersistsAndReloads(t *testing.T) {
	for _, impersonated := range []bool{false, true} {
		mode := "user"
		if impersonated {
			mode = "impersonated"
		}
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/impersonate" {
					if r.Header.Get("Authorization") != "Bearer user-token" {
						t.Error("impersonation did not use user OAuth token")
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"accessToken": "impersonated-token",
						"expireTime":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
					})
					return
				}
				if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "fixture-refresh" {
					t.Error("incorrect refresh exchange")
				}
				_, _ = io.WriteString(w, `{"access_token":"user-token","token_type":"Bearer","expires_in":3600}`)
			}))
			defer server.Close()

			adc := map[string]any{
				"type":             "authorized_user",
				"client_id":        "client",
				"client_secret":    "fixture-secret",
				"refresh_token":    "fixture-refresh",
				"token_uri":        server.URL + "/token",
				"quota_project_id": "billing-project",
			}
			if impersonated {
				adc = map[string]any{
					"type":                              "impersonated_service_account",
					"source_credentials":                adc,
					"service_account_impersonation_url": server.URL + "/impersonate",
					"quota_project_id":                  "billing-project",
				}
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "adc.json")
			data, errMarshal := json.Marshal(adc)
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}

			// Exercise native Google ADC discovery, not just explicit-file import.
			t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", path)
			t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")

			store := NewFileTokenStore()
			manager := NewManager(store, NewVertexADCAuthenticator())
			cfg := &config.Config{AuthDir: filepath.Join(dir, "auth")}

			record, saved, err := manager.Login(context.Background(), "vertex", cfg, &LoginOptions{
				ProjectID: "resource-project",
				Metadata: map[string]string{
					"prefix":   "vertex",
					"location": "us-central1",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if record.AuthKind() != coreauth.AuthKindOAuth ||
				record.Metadata["project_id"] != "resource-project" ||
				record.Metadata["quota_project_id"] != "billing-project" {
				t.Fatal("incorrect ADC classification or project metadata")
			}

			info, errStat := os.Stat(saved)
			if errStat != nil || info.Mode().Perm() != 0o600 {
				t.Fatal("ADC must be persisted privately", errStat)
			}

			loaded, errList := store.List(context.Background())
			if errList != nil || len(loaded) != 1 || loaded[0].AuthKind() != coreauth.AuthKindOAuth || loaded[0].Prefix != "vertex" {
				t.Fatal("ADC did not survive store reload", errList)
			}

			payload, errRead := os.ReadFile(saved)
			if errRead != nil {
				t.Fatal(errRead)
			}
			if strings.Contains(string(payload), "private_key") ||
				strings.Contains(string(payload), "user-token") ||
				strings.Contains(string(payload), "impersonated-token") {
				t.Fatal("ADC must not invent private keys or persist ephemeral access tokens")
			}

			_, _, errImport := manager.Login(context.Background(), "vertex", cfg, &LoginOptions{
				ProjectID: "resource-project",
				Metadata: map[string]string{
					"adc_file": path,
					"prefix":   "vertex",
					"location": "us-central1",
				},
			})
			if errImport != nil {
				t.Fatal("explicit import failed", errImport)
			}
			loaded, errList = store.List(context.Background())
			if errList != nil || len(loaded) != 1 {
				t.Fatal("re-registering the same ADC created a duplicate credential")
			}
		})
	}
}

func TestVertexADCLoginRejectsInvalidInputWithoutSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adc.json")
	if err := os.WriteFile(path, []byte(`{"type":"unsupported-secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewVertexADCAuthenticator().Login(context.Background(), &config.Config{}, &LoginOptions{
		ProjectID: "project",
		Metadata: map[string]string{
			"adc_file": path,
		},
	})
	if err == nil || strings.Contains(err.Error(), "unsupported-secret") {
		t.Fatal("invalid ADC was accepted or its contents leaked")
	}
}

func TestVertexADCRequiresResourceProjectNotQuotaProject(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adc.json")
	data := []byte(`{"type":"authorized_user","client_id":"fixture","refresh_token":"fixture","quota_project_id":"billing-project"}`)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := NewVertexADCAuthenticator().Login(context.Background(), &config.Config{}, &LoginOptions{
		Metadata: map[string]string{
			"adc_file": path,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "-vertex-adc-project is required") {
		t.Fatal("quota project was incorrectly treated as the resource project", err)
	}
}
