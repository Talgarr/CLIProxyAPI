package cmd

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

func TestVertexADCLoginUsesGcloudThenSharedStore(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses a POSIX gcloud shim")
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"fixture-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".config", "gcloud"), 0o700); err != nil {
		t.Fatal(err)
	}

	source := filepath.Join(dir, "source.json")
	data, errMarshal := json.Marshal(map[string]any{
		"type":          "authorized_user",
		"client_id":     "fixture",
		"client_secret": "fixture",
		"refresh_token": "fixture",
		"token_uri":     server.URL,
	})
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	if err := os.WriteFile(source, data, 0o600); err != nil {
		t.Fatal(err)
	}

	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$ADC_TEST_ARGS\"\ncp \"$ADC_TEST_SOURCE\" \"$HOME/.config/gcloud/application_default_credentials.json\"\n"
	if err := os.WriteFile(filepath.Join(dir, "gcloud"), []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}

	argsPath := filepath.Join(dir, "arguments")
	t.Setenv("HOME", dir)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", "")
	t.Setenv("GOOGLE_CLOUD_QUOTA_PROJECT", "")
	t.Setenv("ADC_TEST_ARGS", argsPath)
	t.Setenv("ADC_TEST_SOURCE", source)

	previous := sdkAuth.GetTokenStore()
	store := sdkAuth.NewFileTokenStore()
	sdkAuth.RegisterTokenStore(store)
	defer sdkAuth.RegisterTokenStore(previous)

	errLogin := DoVertexADCLogin(
		&config.Config{AuthDir: filepath.Join(dir, "auth")},
		&LoginOptions{NoBrowser: true},
		VertexADCOptions{
			Login:                     true,
			Project:                   "resource-project",
			ImpersonateServiceAccount: "agent@example.iam.gserviceaccount.com",
		},
	)
	if errLogin != nil {
		t.Fatal(errLogin)
	}

	args, errRead := os.ReadFile(argsPath)
	if errRead != nil {
		t.Fatal(errRead)
	}
	want := "auth\napplication-default\nlogin\n--no-launch-browser\n--impersonate-service-account\nagent@example.iam.gserviceaccount.com\n"
	if string(args) != want {
		t.Fatalf("gcloud did not receive the requested login mode: %s", args)
	}

	records, errList := store.List(context.Background())
	if errList != nil || len(records) != 1 || records[0].Provider != "vertex" || !strings.HasPrefix(records[0].ID, "vertex-adc-") {
		t.Fatal("gcloud login was not registered in the shared store", errList)
	}
}
