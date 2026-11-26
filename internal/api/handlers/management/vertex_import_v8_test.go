package management

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func buildVertexImportMultipartRequest(t *testing.T, targetURL string, fileContent []byte, fields map[string]string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if fileContent != nil {
		part, errPart := writer.CreateFormFile("file", "credentials.json")
		if errPart != nil {
			t.Fatal(errPart)
		}
		if _, errWrite := part.Write(fileContent); errWrite != nil {
			t.Fatal(errWrite)
		}
	}
	for k, v := range fields {
		if errField := writer.WriteField(k, v); errField != nil {
			t.Fatal(errField)
		}
	}
	if errClose := writer.Close(); errClose != nil {
		t.Fatal(errClose)
	}
	req := httptest.NewRequest(http.MethodPost, targetURL, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req
}

func TestImportVertexCredentialV8ADC(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, impersonated := range []bool{false, true} {
		name := "authorized_user"
		if impersonated {
			name = "impersonated_service_account"
		}
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/impersonate" {
					_ = json.NewEncoder(w).Encode(map[string]any{
						"accessToken": "impersonated-token",
						"expireTime":  time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
					})
					return
				}
				_, _ = io.WriteString(w, `{"access_token":"user-token","token_type":"Bearer","expires_in":3600}`)
			}))
			defer server.Close()

			adc := map[string]any{
				"type":             "authorized_user",
				"client_id":        "fixture-client",
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
			rawADC, errMarshal := json.Marshal(adc)
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}

			authDir := t.TempDir()
			store := sdkAuth.NewFileTokenStore()
			store.SetBaseDir(authDir)

			h := &Handler{
				cfg:        &config.Config{AuthDir: authDir},
				tokenStore: store,
			}
			router := gin.New()
			router.POST("/v8/management/oauth/import", h.ImportOAuthV8)

			req := buildVertexImportMultipartRequest(
				t,
				"/v8/management/oauth/import?provider=vertex",
				rawADC,
				map[string]string{
					"project_id": "resource-project",
					"location":   "us-central1",
					"prefix":     "vertex",
				},
			)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %s", rec.Code, rec.Body.String())
			}

			var resp map[string]any
			if errDecode := json.Unmarshal(rec.Body.Bytes(), &resp); errDecode != nil {
				t.Fatalf("decode response: %v", errDecode)
			}
			if resp["status"] != "ok" || resp["auth_mode"] != "adc" || resp["project_id"] != "resource-project" ||
				resp["location"] != "us-central1" || resp["quota_project_id"] != "billing-project" || resp["prefix"] != "vertex" {
				t.Fatalf("unexpected response: %#v", resp)
			}

			savedPath, _ := resp["auth-file"].(string)
			info, errStat := os.Stat(savedPath)
			if errStat != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("saved ADC file permissions = %v, err = %v", info, errStat)
			}
			records, errList := store.List(context.Background())
			if errList != nil || len(records) != 1 || records[0].AuthKind() != coreauth.AuthKindOAuth || records[0].Prefix != "vertex" {
				t.Fatalf("persisted ADC records = %#v, err = %v", records, errList)
			}
		})
	}
}

func TestImportVertexCredentialV8ValidationAndServiceAccount(t *testing.T) {
	gin.SetMode(gin.TestMode)

	authDir := t.TempDir()
	store := sdkAuth.NewFileTokenStore()
	store.SetBaseDir(authDir)

	h := &Handler{
		cfg:        &config.Config{AuthDir: authDir},
		tokenStore: store,
	}
	router := gin.New()
	router.POST("/v8/management/oauth/import", h.ImportOAuthV8)

	// Missing project_id on user ADC returns 400 and does not echo secrets.
	adcData := []byte(`{"type":"authorized_user","client_id":"c","refresh_token":"super-secret-refresh"}`)
	reqMissing := buildVertexImportMultipartRequest(t, "/v8/management/oauth/import?provider=vertex", adcData, nil)
	recMissing := httptest.NewRecorder()
	router.ServeHTTP(recMissing, reqMissing)
	if recMissing.Code != http.StatusBadRequest {
		t.Fatalf("missing project status = %d, want 400", recMissing.Code)
	}
	if strings.Contains(recMissing.Body.String(), "super-secret-refresh") {
		t.Fatalf("error body leaked secret: %s", recMissing.Body.String())
	}

	// Service-account JSON continues to work on v8 import.
	key, errKey := rsa.GenerateKey(rand.Reader, 2048)
	if errKey != nil {
		t.Fatal(errKey)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	saJSON, errMarshal := json.Marshal(map[string]any{
		"type":         "service_account",
		"project_id":   "sa-project",
		"client_email": "sa@sa-project.iam.gserviceaccount.com",
		"private_key":  string(pemKey),
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	reqSA := buildVertexImportMultipartRequest(t, "/v8/management/oauth/import?provider=vertex", saJSON, map[string]string{"prefix": "team"})
	recSA := httptest.NewRecorder()
	router.ServeHTTP(recSA, reqSA)
	if recSA.Code != http.StatusOK {
		t.Fatalf("service account status = %d, want 200; body = %s", recSA.Code, recSA.Body.String())
	}
	var saResp map[string]any
	if errDecode := json.Unmarshal(recSA.Body.Bytes(), &saResp); errDecode != nil {
		t.Fatal(errDecode)
	}
	if saResp["auth_mode"] != "service_account" || saResp["project_id"] != "sa-project" || saResp["prefix"] != "team" {
		t.Fatalf("unexpected service account response: %#v", saResp)
	}
}
