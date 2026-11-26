package executor

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestVertexADCRequestPaths(t *testing.T) {
	var modelCalls, tokenCalls atomic.Int32
	expectedQuotaProject := "quota-project"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenCalls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"access_token":"adc-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		modelCalls.Add(1)
		if r.Header.Get("Authorization") != "Bearer adc-token" ||
			r.Header.Get("X-Goog-Api-Key") != "" ||
			r.Header.Get("X-Goog-User-Project") != expectedQuotaProject {
			t.Errorf("Vertex request did not use ADC bearer auth and expected quota project %q (got %q)", expectedQuotaProject, r.Header.Get("X-Goog-User-Project"))
		}
		if !strings.Contains(r.URL.Path, "/projects/resource-project/locations/global/") {
			t.Errorf("incorrect resource project/location: %s", r.URL.Path)
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/chat/completions"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"id":"chatcmpl-adc","object":"chat.completion","model":"deepseek-ai/deepseek-v4.1-flash-maas","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop"}]}`)
		case strings.HasSuffix(r.URL.Path, ":countTokens"):
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"totalTokens":2}`)
		case strings.HasSuffix(r.URL.Path, ":streamGenerateContent"):
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: {\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"hello\"}]},\"finishReason\":\"STOP\"}]}\n\n")
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"candidates":[{"content":{"role":"model","parts":[{"text":"hello"}]},"finishReason":"STOP"}]}`)
		}
	}))
	defer server.Close()

	target, errParse := url.Parse(server.URL)
	if errParse != nil {
		t.Fatal(errParse)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	defer transport.CloseIdleConnections()

	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", issue6258RedirectTransport{
		target: target,
		base:   transport,
	})
	auth := &cliproxyauth.Auth{
		ID:       "adc",
		Provider: "vertex",
		Metadata: map[string]any{
			"project_id": "resource-project",
			"location":   "global",
			// An old top-level access token must not turn ADC into API-key auth.
			"access_token": "stale-token",
			"adc": map[string]any{
				"type":             "authorized_user",
				"client_id":        "fixture",
				"client_secret":    "fixture",
				"refresh_token":    "fixture",
				"token_uri":        server.URL + "/token",
				"quota_project_id": "quota-project",
			},
		},
	}

	executor := NewGeminiVertexExecutor(&config.Config{})
	req := cliproxyexecutor.Request{
		Model:   "gemini-2.5-flash",
		Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"hello"}]}]}`),
	}
	opts := cliproxyexecutor.Options{SourceFormat: sdktranslator.FormatGemini}

	if _, err := executor.Execute(ctx, auth, req, opts); err != nil {
		t.Fatal(err)
	}

	stream, errStream := executor.ExecuteStream(ctx, auth, req, opts)
	if errStream != nil {
		t.Fatal(errStream)
	}
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
	}

	if _, err := executor.CountTokens(ctx, auth, req, opts); err != nil {
		t.Fatal(err)
	}

	openAPIAuth := auth.Clone()
	openAPIAuth.Metadata["openapi"] = true
	openAPIReq := cliproxyexecutor.Request{
		Model:   "deepseek-ai/deepseek-v4.1-flash-maas",
		Payload: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
	}
	openAPIOpts := cliproxyexecutor.Options{
		SourceFormat:   sdktranslator.FormatOpenAI,
		ResponseFormat: sdktranslator.FormatOpenAI,
	}
	if _, err := executor.Execute(ctx, openAPIAuth, openAPIReq, openAPIOpts); err != nil {
		t.Fatal("OpenAPI ADC failed", err)
	}

	// Explicit custom header must override the ADC quota project.
	expectedQuotaProject = "custom-quota-project"
	overrideAuth := auth.Clone()
	overrideAuth.Attributes = map[string]string{
		"header:X-Goog-User-Project": "custom-quota-project",
	}
	if _, err := executor.Execute(ctx, overrideAuth, req, opts); err != nil {
		t.Fatal("custom quota header override failed", err)
	}

	httpReq, errNewReq := http.NewRequestWithContext(ctx, http.MethodPost, "https://aiplatform.googleapis.com/v1/projects/resource-project/locations/global/test", nil)
	if errNewReq != nil {
		t.Fatal(errNewReq)
	}
	httpReq.Header.Set("X-Goog-Api-Key", "old-key")
	if err := executor.PrepareRequest(httpReq, auth); err != nil {
		t.Fatal(err)
	}
	if httpReq.Header.Get("Authorization") != "Bearer adc-token" ||
		httpReq.Header.Get("X-Goog-Api-Key") != "" ||
		httpReq.Header.Get("X-Goog-User-Project") != "quota-project" {
		t.Fatal("PrepareRequest did not apply ADC")
	}

	if tokenCalls.Load() != 1 || modelCalls.Load() != 5 {
		t.Fatalf("expected one token exchange and five model requests; got %d and %d", tokenCalls.Load(), modelCalls.Load())
	}
}

func TestVertexADCUsesCredentialProxyNotRequestProxy(t *testing.T) {
	var authHits, requestHits atomic.Int32
	authProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"proxied-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer authProxy.Close()

	requestProxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestHits.Add(1)
		http.Error(w, "execution proxy must not receive refresh credentials", http.StatusInternalServerError)
	}))
	defer requestProxy.Close()

	ctx := cliproxyexecutor.WithRequestProxyURL(context.Background(), requestProxy.URL)
	auth := &cliproxyauth.Auth{
		ID:       "proxy-adc",
		ProxyURL: authProxy.URL,
		Metadata: map[string]any{
			"adc": map[string]any{
				"type":          "authorized_user",
				"refresh_token": "fixture",
				"token_uri":     "http://oauth.example/token",
			},
		},
	}

	executor := NewGeminiVertexExecutor(&config.Config{})
	if token, err := executor.accessToken(ctx, auth, nil); err != nil || token != "proxied-token" {
		t.Fatal("ADC token did not use credential proxy", err)
	}
	if authHits.Load() != 1 || requestHits.Load() != 0 {
		t.Fatal("ADC refresh credentials reached the wrong proxy")
	}
}
