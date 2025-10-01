package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	configStr := `
proxies:
  app.com:
    rate_limit:
      rate: 10
      burst: 10
      cooldown: 60000
    target: "localhost:8080"
    routes:
      - pattern: "/api/*"
        target: "localhost:3000"
     
      - pattern: "/v1/*"
        target: "localhost:8001"
        rewrite:
          from: "^/v1/api"
          to: "/$1"
      
      - pattern: "/health"
        target: "localhost:8080"
        rate_limit:
          burst: 10
          rate: 10
          cooldown: 60000
 `

	config := NewConfig()
	err := config.LoadBytes([]byte(configStr))
	require.NoError(t, err)

	proxy := config.GetProxy("app.com")
	require.NotNil(t, proxy)
	require.NotNil(t, proxy.Limiter)
	require.Equal(t, "localhost:8080", proxy.Target)

	route := proxy.MatchRoute("/v1/api")
	require.Equal(t, "/", route.RewrittenPath)

	route = proxy.MatchRoute("/api/create")
	require.Equal(t, "/api/create", route.RewrittenPath)
	require.Equal(t, "localhost:3000", route.Target)

	route = proxy.MatchRoute("/health")
	require.Equal(t, "/health", route.RewrittenPath)
	require.NotNil(t, route.limiter)
}
