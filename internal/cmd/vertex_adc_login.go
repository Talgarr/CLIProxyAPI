package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
)

// VertexADCOptions selects Google ADC login or registration of existing ADC.
type VertexADCOptions struct {
	Login                     bool
	File                      string
	Project                   string
	Location                  string
	Prefix                    string
	QuotaProject              string
	ImpersonateServiceAccount string
}

// DoVertexADCLogin uses Google's supported login tooling and the shared auth
// manager. gcloud is needed only for interactive acquisition, never at runtime.
func DoVertexADCLogin(cfg *config.Config, login *LoginOptions, opts VertexADCOptions) error {
	if login == nil {
		login = &LoginOptions{}
	}
	if !opts.Login && opts.ImpersonateServiceAccount != "" {
		return fmt.Errorf("vertex ADC: impersonation option requires -vertex-adc-login; use an existing impersonated ADC file with -vertex-adc")
	}
	if opts.Login && (opts.File != "" || os.Getenv("GOOGLE_APPLICATION_CREDENTIALS") != "") {
		return fmt.Errorf("vertex ADC: use -vertex-adc for an existing file or GOOGLE_APPLICATION_CREDENTIALS; gcloud login creates credentials in its default location")
	}
	if opts.Login && strings.TrimSpace(opts.Project) == "" {
		return fmt.Errorf("vertex ADC: -vertex-adc-project is required for gcloud user login")
	}
	if opts.Login {
		args := []string{"auth", "application-default", "login"}
		if login.NoBrowser {
			args = append(args, "--no-launch-browser")
		}
		if opts.ImpersonateServiceAccount != "" {
			args = append(args, "--impersonate-service-account", opts.ImpersonateServiceAccount)
		}
		command := exec.CommandContext(context.Background(), "gcloud", args...)
		command.Stdin = os.Stdin
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if errRun := command.Run(); errRun != nil {
			return fmt.Errorf("vertex ADC: gcloud login failed; install gcloud or register existing ADC with -vertex-adc")
		}
	}

	authOpts := &sdkAuth.LoginOptions{
		ProjectID: opts.Project,
		ProxyURL:  login.ProxyURL,
		Metadata: map[string]string{
			"adc_file":         opts.File,
			"location":         opts.Location,
			"prefix":           opts.Prefix,
			"quota_project_id": opts.QuotaProject,
		},
	}
	_, savedPath, errLogin := newAuthManager().Login(context.Background(), "vertex", cfg, authOpts)
	if errLogin != nil {
		return errLogin
	}
	if savedPath != "" {
		fmt.Printf("Vertex ADC authentication saved to %s\n", savedPath)
	}
	fmt.Println("Vertex ADC authentication successful!")
	return nil
}
