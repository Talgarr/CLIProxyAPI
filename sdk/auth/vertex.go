package auth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/vertex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"golang.org/x/oauth2"
)

// VertexADCAuthenticator registers ADC in the same auth store as OAuth logins.
type VertexADCAuthenticator struct{}

// NewVertexADCAuthenticator constructs a Vertex ADC authenticator.
func NewVertexADCAuthenticator() *VertexADCAuthenticator {
	return &VertexADCAuthenticator{}
}

func (*VertexADCAuthenticator) Provider() string {
	return "vertex"
}

func (*VertexADCAuthenticator) RefreshLead() *time.Duration {
	return nil
}

func (*VertexADCAuthenticator) Login(ctx context.Context, cfg *config.Config, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vertex ADC: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}

	var data []byte
	if path := strings.TrimSpace(opts.Metadata["adc_file"]); path != "" {
		var errRead error
		data, errRead = os.ReadFile(path)
		if errRead != nil {
			return nil, fmt.Errorf("vertex ADC: cannot read credential file")
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("vertex ADC: credential file is empty")
		}
	}

	return BuildVertexADCAuth(ctx, cfg, data, opts)
}

// BuildVertexADCAuth validates raw or ambient Google Application Default Credentials,
// verifies token acquisition, and returns a persistable Vertex auth record.
// When data is empty, standard Google ADC discovery is used on the current host.
func BuildVertexADCAuth(ctx context.Context, cfg *config.Config, data []byte, opts *LoginOptions) (*coreauth.Auth, error) {
	if cfg == nil {
		return nil, fmt.Errorf("vertex ADC: configuration is required")
	}
	if opts == nil {
		opts = &LoginOptions{}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, util.SetProxy(&cfg.SDKConfig, &http.Client{}))

	creds, errLoad := vertex.LoadADC(ctx, data)
	if errLoad != nil {
		return nil, fmt.Errorf("vertex ADC: cannot load credentials; run gcloud auth application-default login or specify -vertex-adc-file")
	}

	project := strings.TrimSpace(opts.ProjectID)
	if project == "" {
		project = strings.TrimSpace(creds.ProjectID)
	}
	if project == "" {
		return nil, fmt.Errorf("vertex ADC: -vertex-adc-project is required when ADC does not specify a resource project")
	}
	if strings.ContainsAny(project, "/\\?#\r\n\x00 ") {
		return nil, fmt.Errorf("vertex ADC: invalid resource project")
	}

	location := strings.TrimSpace(opts.Metadata["location"])
	if location == "" {
		location = "global"
	}
	if strings.ContainsAny(location, "/\\?#\r\n\x00 ") {
		return nil, fmt.Errorf("vertex ADC: invalid location")
	}

	prefix := strings.Trim(strings.TrimSpace(opts.Metadata["prefix"]), "/")
	if strings.ContainsAny(prefix, "/\\\r\n\x00 ") {
		return nil, fmt.Errorf("vertex ADC: prefix must be a single segment")
	}

	var adc map[string]any
	if len(creds.JSON) > 0 {
		if errJSON := json.Unmarshal(creds.JSON, &adc); errJSON != nil {
			return nil, fmt.Errorf("vertex ADC: invalid credential JSON")
		}
	}

	quota := strings.TrimSpace(opts.Metadata["quota_project_id"])
	if quota == "" {
		quota = strings.TrimSpace(os.Getenv("GOOGLE_CLOUD_QUOTA_PROJECT"))
	}
	if quota == "" && adc != nil {
		quota, _ = adc["quota_project_id"].(string)
		quota = strings.TrimSpace(quota)
	}
	if strings.ContainsAny(quota, "/\\?#\r\n\x00 ") {
		return nil, fmt.Errorf("vertex ADC: invalid quota project")
	}

	if _, errToken := creds.TokenSource.Token(); errToken != nil {
		// OAuth error bodies can contain credentials. Do not echo them.
		return nil, fmt.Errorf("vertex ADC: token acquisition failed; check ADC login and impersonation permissions")
	}

	// Identity includes the credential so separate accounts do not overwrite each other.
	identity := sha256.Sum256(append(append([]byte(project+"\x00"+location+"\x00"+prefix+"\x00"), creds.JSON...), []byte(quota)...))
	name := fmt.Sprintf("vertex-adc-%x.json", identity[:12])
	label := "Vertex ADC (" + project + ")"

	metadata := map[string]any{
		"type":             "vertex",
		"auth_kind":        coreauth.AuthKindOAuth,
		"project_id":       project,
		"location":         location,
		"prefix":           prefix,
		"quota_project_id": quota,
		"label":            label,
		"use_adc":          adc == nil,
	}
	if adc != nil {
		metadata["adc"] = adc
	}

	storage := &vertex.VertexCredentialStorage{
		ADC:            adc,
		UseADC:         adc == nil,
		ProjectID:      project,
		Location:       location,
		Prefix:         prefix,
		QuotaProjectID: quota,
	}

	return &coreauth.Auth{
		ID:       name,
		FileName: name,
		Provider: "vertex",
		Prefix:   prefix,
		Label:    label,
		Storage:  storage,
		Metadata: metadata,
	}, nil
}
