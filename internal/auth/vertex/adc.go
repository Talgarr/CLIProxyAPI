package vertex

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/MoeForge/moego/json"
	"golang.org/x/oauth2/google"
)

const CloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

// UsesADC distinguishes ADC from service-account and API-key auth records.
func UsesADC(metadata map[string]any) bool {
	if enabled, _ := metadata["use_adc"].(bool); enabled {
		return true
	}
	_, ok := metadata["adc"].(map[string]any)
	return ok
}

// LoadADC uses the Google library for both imported and ambient credentials.
// Empty data selects the standard ADC discovery order on this host.
func LoadADC(ctx context.Context, data []byte) (*google.Credentials, error) {
	if len(data) == 0 {
		return google.FindDefaultCredentials(ctx, CloudPlatformScope)
	}
	return google.CredentialsFromJSON(ctx, data, CloudPlatformScope)
}

func ADCJSON(metadata map[string]any) ([]byte, error) {
	if raw, ok := metadata["adc"].(map[string]any); ok {
		data, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("vertex: invalid ADC credential")
		}
		return data, nil
	}
	if enabled, _ := metadata["use_adc"].(bool); enabled {
		return nil, nil
	}
	return nil, fmt.Errorf("vertex: missing ADC credential")
}

// QuotaProject keeps the resource project separate from the quota project.
func QuotaProject(metadata map[string]any) string {
	if value, _ := metadata["quota_project_id"].(string); strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	if adc, ok := metadata["adc"].(map[string]any); ok {
		value, _ := adc["quota_project_id"].(string)
		return strings.TrimSpace(value)
	}
	return ""
}

func ApplyQuotaProject(req *http.Request, metadata map[string]any) {
	if UsesADC(metadata) {
		if project := QuotaProject(metadata); project != "" {
			req.Header.Set("X-Goog-User-Project", project)
		}
	}
}
