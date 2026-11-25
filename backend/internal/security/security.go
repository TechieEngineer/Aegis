// Package security contains dependency-free validation and request filtering.
package security

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

var rules = []struct {
	name    string
	pattern *regexp.Regexp
}{
	{"SQLi", regexp.MustCompile(`(?i)(\bunion\s+(all\s+)?select\b|['"]\s*(or|and)\s+['"0-9]+\s*=|\b(?:drop|alter)\s+table\b|\bselect\b.{0,80}\bfrom\b)`)},
	{"XSS", regexp.MustCompile(`(?i)(<\s*/?\s*(script|iframe|svg)\b|\bon[a-z]+\s*=\s*['"]|javascript\s*:)`)},
	{"Traversal", regexp.MustCompile(`(?:^|[/\\])\.\.(?:[/\\]|$)`)},
}

func Inspect(value string) string {
	for i := 0; i < 3; i++ {
		for _, r := range rules {
			if r.pattern.MatchString(value) {
				return r.name
			}
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil || decoded == value {
			break
		}
		value = decoded
	}
	return ""
}
func InspectJSON(v any) string {
	switch t := v.(type) {
	case string:
		return Inspect(t)
	case []any:
		for _, x := range t {
			if hit := InspectJSON(x); hit != "" {
				return hit
			}
		}
	case map[string]any:
		for k, x := range t {
			if hit := Inspect(k); hit != "" {
				return hit
			}
			if hit := InspectJSON(x); hit != "" {
				return hit
			}
		}
	}
	return ""
}
func InspectBody(b []byte) string {
	var v any
	if json.Unmarshal(b, &v) == nil {
		return InspectJSON(v)
	}
	return Inspect(string(b))
}

var hostRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var forbidden = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func PublicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.Zone() != "" {
		return false
	}
	// Conservatively allow only the currently allocated IPv6 global unicast space.
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range forbidden {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
func Host(raw string, allowed map[string]bool) (string, error) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if len(h) > 253 || !strings.Contains(h, ".") {
		return "", errors.New("use an approved DNS hostname")
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return "", errors.New("IP literals are not permitted")
	}
	for _, label := range strings.Split(h, ".") {
		if !hostRE.MatchString(label) {
			return "", errors.New("invalid DNS hostname")
		}
	}
	if !allowed[h] {
		return "", errors.New("hostname is not approved")
	}
	return h, nil
}
func Random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
