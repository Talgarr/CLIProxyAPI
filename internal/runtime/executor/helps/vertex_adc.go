package helps

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/vertex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"golang.org/x/oauth2"
)

type vertexADCToken struct {
	mu    sync.Mutex
	token *oauth2.Token
}

// VertexADCTokenCache caches access tokens, never request-bound TokenSources.
// A refresh uses the current request context so cancellation of an earlier
// request cannot break future refreshes. Each credential refreshes independently.
type VertexADCTokenCache struct {
	mu      sync.Mutex
	entries map[[32]byte]*vertexADCToken
}

func (c *VertexADCTokenCache) Token(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) (string, error) {
	data, errJSON := vertex.ADCJSON(auth.Metadata)
	if errJSON != nil {
		return "", errJSON
	}
	proxy := auth.ProxyURL
	if proxy == "" && cfg != nil {
		proxy = cfg.ProxyURL
	}
	key := sha256.Sum256(append([]byte(auth.ID+"\x00"+proxy+"\x00"), data...))
	c.mu.Lock()
	if c.entries == nil {
		c.entries = make(map[[32]byte]*vertexADCToken)
	}
	entry := c.entries[key]
	if entry == nil {
		// Bound retained tokens after credential/config rotation.
		if len(c.entries) >= 256 {
			clear(c.entries)
		}
		entry = &vertexADCToken{}
		c.entries[key] = entry
	}
	c.mu.Unlock()
	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.token.Valid() {
		return entry.token.AccessToken, nil
	}
	ctx, cancel := context.WithTimeout(cliproxyexecutor.WithoutRequestProxyURL(ctx), 2*time.Minute)
	defer cancel()
	ctx = context.WithValue(ctx, oauth2.HTTPClient, NewProxyAwareHTTPClient(ctx, cfg, auth, 0))
	creds, errLoad := vertex.LoadADC(ctx, data)
	if errLoad != nil {
		return "", fmt.Errorf("vertex ADC: cannot load credentials")
	}
	token, errToken := creds.TokenSource.Token()
	if errToken != nil {
		return "", fmt.Errorf("vertex ADC: token acquisition failed")
	}
	entry.token = token
	return token.AccessToken, nil
}

// VertexADCQuotaAuth supplies quota headers to the shared OpenAI executor too,
// unless an explicit X-Goog-User-Project custom header is already configured.
func VertexADCQuotaAuth(auth *cliproxyauth.Auth) *cliproxyauth.Auth {
	if auth == nil || !vertex.UsesADC(auth.Metadata) {
		return auth
	}
	project := vertex.QuotaProject(auth.Metadata)
	if project == "" {
		return auth
	}
	cloned := auth.Clone()
	if cloned.Attributes == nil {
		cloned.Attributes = make(map[string]string)
	}
	for k := range cloned.Attributes {
		if strings.EqualFold(k, "header:X-Goog-User-Project") {
			return cloned
		}
	}
	cloned.Attributes["header:X-Goog-User-Project"] = project
	return cloned
}
