// Package config implements a user-defined configuration for tcprp with path rewriting.
package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/Dyastin-0/tcprp/core/limiter"
	"github.com/Dyastin-0/tcprp/core/metrics"
	"gopkg.in/yaml.v3"
)

const (
	ProtoTLS   = "tls"
	ProtoTCP   = "tcp"
	ProtoHTTP  = "http"
	ProtoHTTPS = "https"
)

type LimiterConfig struct {
	Rate     int   `yaml:"rate"`
	Burst    int   `yaml:"burst"`
	Cooldown int64 `yaml:"cooldown"`
}

type RouteConfig struct {
	Pattern     string         `yaml:"pattern"`
	Target      string         `yaml:"target"`
	TLS         bool           `yaml:"tls,omitempty"`
	RewriteRule *RewriteRule   `yaml:"rewrite,omitempty"`
	Limiter     *LimiterConfig `yaml:"rate_limit,omitempty"`
}

type ProxyConfig struct {
	Target  string         `yaml:"target"`
	TLS     bool           `yaml:"tls,omitempty"`
	Routes  []*RouteConfig `yaml:"routes,omitempty"`
	Limiter *LimiterConfig `yaml:"rate_limit,omitempty"`
}

// ConfigFile represents the YAML structure.
type ConfigFile struct {
	Proxies map[string]ProxyConfig `yaml:"proxies"`
}

// Config holds the loaded configuration.
type Config struct {
	Proxies *Trie[*Proxy]
}

// NewConfig creates a new configuration instance.
func NewConfig() *Config {
	return &Config{
		Proxies: NewTrie[*Proxy](),
	}
}

// Load loads configuration from a YAML file.
func (c *Config) Load(filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	return c.LoadBytes(data)
}

// LoadBytes loads configuration from YAML bytes.
func (c *Config) LoadBytes(data []byte) error {
	var configFile ConfigFile
	if err := yaml.Unmarshal(data, &configFile); err != nil {
		return fmt.Errorf("failed to parse yaml: %w", err)
	}
	return c.loadProxies(configFile)
}

// loadProxies loads proxy configurations into the trie.
func (c *Config) loadProxies(configFile ConfigFile) error {
	for domain, proxy := range configFile.Proxies {
		if proxy.Target == "" {
			return fmt.Errorf("empty target for domain '%s'", domain)
		}

		p := &Proxy{
			Target:  proxy.Target,
			TLS:     proxy.TLS,
			Metrics: metrics.New(),
		}

		if proxy.Limiter != nil {
			p.Limiter = limiter.New(
				limiter.WithBurst(proxy.Limiter.Burst),
				limiter.WithRPS(proxy.Limiter.Rate),
				limiter.WithCooldown(time.Duration(proxy.Limiter.Cooldown)),
			)
		}

		if len(proxy.Routes) > 0 {
			p.Routes = make([]*Route, len(proxy.Routes))
			for i, routeConf := range proxy.Routes {
				route := &Route{
					Target:      routeConf.Target,
					TLS:         routeConf.TLS,
					Pattern:     routeConf.Pattern,
					RewriteRule: routeConf.RewriteRule,
				}

				if routeConf.Limiter != nil {
					route.Limiter = limiter.New(
						limiter.WithBurst(routeConf.Limiter.Burst),
						limiter.WithRPS(routeConf.Limiter.Rate),
						limiter.WithCooldown(time.Duration(routeConf.Limiter.Cooldown)),
					)
				}

				p.Routes[i] = route
			}

			for _, route := range p.Routes {
				if route.Target == "" {
					return fmt.Errorf("empty target for route '%s' in domain '%s'", route.Pattern, domain)
				}
				if route.RewriteRule != nil && route.RewriteRule.From != "" {
					if _, err := regexp.Compile(route.RewriteRule.From); err != nil {
						return fmt.Errorf("invalid regex '%s' in rewrite rule for domain '%s': %w",
							route.RewriteRule.From, domain, err)
					}
				}
			}
		}

		p.sortRoutes()
		c.Proxies.Set(domain, p)
	}
	return nil
}

// GetProxy finds a proxy for the given domain.
func (c *Config) GetProxy(domain string) *Proxy {
	if proxy := c.Proxies.Get(domain); proxy != nil {
		return *proxy
	}
	return nil
}

// AddProxy adds a single proxy configuration to the given domain.
func (c *Config) AddProxy(domain, target string) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}
	proxy := &Proxy{
		Target:  target,
		Metrics: metrics.New(),
	}
	c.Proxies.Set(domain, proxy)
	return nil
}

// AddProxyWithRoutes adds a proxy with enhanced routes.
func (c *Config) AddProxyWithRoutes(domain, target string, routes []*Route) error {
	if target == "" {
		return fmt.Errorf("target cannot be empty")
	}

	proxy := &Proxy{
		Target:  target,
		Metrics: metrics.New(),
		Routes:  make([]*Route, len(routes)),
	}

	// Validate and copy routes
	for i, route := range routes {
		if route.Target == "" {
			return fmt.Errorf("empty target for route '%s'", route.Pattern)
		}
		if route.RewriteRule != nil && route.RewriteRule.From != "" {
			if _, err := regexp.Compile(route.RewriteRule.From); err != nil {
				return fmt.Errorf("invalid regex '%s' in rewrite rule: %w", route.RewriteRule.From, err)
			}
		}
		proxy.Routes[i] = route
	}

	proxy.sortRoutes()
	c.Proxies.Set(domain, proxy)
	return nil
}
