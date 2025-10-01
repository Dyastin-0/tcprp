package config

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Dyastin-0/tcprp/core/limiter"
	"github.com/Dyastin-0/tcprp/core/metrics"
)

// RewriteRule represents a URL path rewriting rule.
type RewriteRule struct {
	From string `yaml:"from"`
	To   string `yaml:"to"`
}

// Route represents an HTTP route pattern, its target, and optional rewrite rules.
type Route struct {
	Pattern     string       `yaml:"pattern"`
	Target      string       `yaml:"target"`
	RewriteRule *RewriteRule `yaml:"rewrite,omitempty"`
	Limiter     *limiter.Limiter
	regex       *regexp.Regexp
}

// RouteResult contains the matched route information and rewritten path.
type RouteResult struct {
	Target        string
	RewrittenPath string
	Matched       bool
	limiter       *limiter.Limiter
}

// Proxy represents a proxy configuration for a domain.
type Proxy struct {
	Target       string
	Metrics      *metrics.Metrics
	Routes       []*Route
	Limiter      *limiter.Limiter
	sortedRoutes []*Route
}

// sortRoutes creates a sorted slice of route patterns.
func (p *Proxy) sortRoutes() {
	if len(p.Routes) > 0 {
		p.sortedRoutes = make([]*Route, len(p.Routes))
		copy(p.sortedRoutes, p.Routes)
	} else {
		p.sortedRoutes = nil
		return
	}

	for i := range p.sortedRoutes {
		if p.sortedRoutes[i].RewriteRule != nil {
			regex, err := regexp.Compile(p.sortedRoutes[i].RewriteRule.From)
			if err == nil {
				p.sortedRoutes[i].regex = regex
			}
		}
	}

	sort.Slice(p.sortedRoutes, func(i, j int) bool {
		if len(p.sortedRoutes[i].Pattern) != len(p.sortedRoutes[j].Pattern) {
			return len(p.sortedRoutes[i].Pattern) > len(p.sortedRoutes[j].Pattern)
		}
		return p.sortedRoutes[i].Pattern < p.sortedRoutes[j].Pattern
	})
}

// MatchRoute finds the best matching route for the given path and returns route result with rewritten path.
func (p *Proxy) MatchRoute(path string) RouteResult {
	for _, route := range p.sortedRoutes {
		if matchesRoute(path, route.Pattern) {
			result := RouteResult{
				Target:        route.Target,
				RewrittenPath: path,
				limiter:       route.Limiter,
				Matched:       true,
			}

			if route.RewriteRule != nil {
				result.RewrittenPath = p.applyRewrite(path, route)
			}

			return result
		}
	}

	return RouteResult{
		Target:        p.Target,
		RewrittenPath: path,
		limiter:       p.Limiter,
		Matched:       false,
	}
}

// applyRewrite applies the rewrite rule to the given path.
func (p *Proxy) applyRewrite(path string, route *Route) string {
	if route.RewriteRule == nil {
		return path
	}

	// Use compiled regex if available
	if route.regex != nil {
		return route.regex.ReplaceAllString(path, route.RewriteRule.To)
	}

	// Fallback to simple string replacement
	return strings.ReplaceAll(path, route.RewriteRule.From, route.RewriteRule.To)
}

// matchesRoute checks if a path matches a route pattern.
func matchesRoute(path, pattern string) bool {
	if path == pattern {
		return true
	}

	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return strings.HasPrefix(path, prefix+"/") || path == prefix
	}

	if strings.HasPrefix(path, pattern) {
		if len(path) == len(pattern) {
			return true
		}
		if len(path) > len(pattern) && path[len(pattern)] == '/' {
			return true
		}
	}

	return false
}

// AddRoute adds an enhanced route to the proxy.
func (p *Proxy) AddRoute(pattern, target string, rewrite *RewriteRule) {
	route := &Route{
		Pattern:     pattern,
		Target:      target,
		RewriteRule: rewrite,
	}

	p.Routes = append(p.Routes, route)
	p.sortRoutes()
}

// RemoveRoute removes a route by pattern.
func (p *Proxy) RemoveRoute(pattern string) bool {
	for i, route := range p.Routes {
		if route.Pattern == pattern {
			p.Routes = append(p.Routes[:i], p.Routes[i+1:]...)
			p.sortRoutes()
			return true
		}
	}
	return false
}
