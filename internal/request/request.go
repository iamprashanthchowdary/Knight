// Package request defines the normalized view of an HTTP request that the rule
// engine inspects. Normalization (URL-decoding, lower-casing) happens here so
// every rule sees the same canonical form and attackers cannot slip a payload
// past a signature with %2e%2e or MiXeD case.
package request

import (
	"net/url"
	"strings"
)

// Context is the normalized, ready-to-inspect form of a request.
type Context struct {
	IP        string
	Method    string
	Path      string // decoded, lower-cased path
	Query     string // decoded, lower-cased query string
	UserAgent string
	Referer   string
	Cookie    string
	Body      string // optional; empty unless the body was captured

	// combined is every inspectable field joined once, used by the
	// Aho-Corasick prefilter for a single-pass scan.
	combined string
}

// decode URL-decodes once (best effort) and lower-cases.
func decode(s string) string {
	if s == "" {
		return ""
	}
	if d, err := url.QueryUnescape(s); err == nil {
		s = d
	}
	return strings.ToLower(s)
}

// New builds a normalized Context from raw request fields.
func New(ip, method, rawURI, userAgent, referer, cookie, body string) *Context {
	path, query := rawURI, ""
	if i := strings.IndexByte(rawURI, '?'); i >= 0 {
		path, query = rawURI[:i], rawURI[i+1:]
	}
	c := &Context{
		IP:        ip,
		Method:    strings.ToUpper(method),
		Path:      decode(path),
		Query:     decode(query),
		UserAgent: strings.ToLower(userAgent),
		Referer:   decode(referer),
		Cookie:    decode(cookie),
		Body:      decode(body),
	}
	c.combined = strings.Join([]string{
		c.Path, c.Query, c.UserAgent, c.Referer, c.Cookie, c.Body,
	}, "\n")
	return c
}

// Combined returns the single scan buffer for the prefilter.
func (c *Context) Combined() string { return c.combined }

// Target returns the normalized text for a named inspection target.
func (c *Context) Target(name string) string {
	switch name {
	case "path":
		return c.Path
	case "query":
		return c.Query
	case "uri":
		if c.Query == "" {
			return c.Path
		}
		return c.Path + "?" + c.Query
	case "user_agent", "ua":
		return c.UserAgent
	case "referer":
		return c.Referer
	case "cookie":
		return c.Cookie
	case "body":
		return c.Body
	case "any", "":
		return c.combined
	default:
		return ""
	}
}
