package security

import (
	"net/netip"
	"testing"
)

func TestWAF(t *testing.T) {
	for _, v := range []string{"' OR 1=1", "%3Cscript%3E", "/a/%252e%252e/b", "UNION SELECT x"} {
		if Inspect(v) == "" {
			t.Errorf("missed %q", v)
		}
	}
	for _, v := range []string{"normal note", "select a color", "hello/world"} {
		if Inspect(v) != "" {
			t.Errorf("false positive %q", v)
		}
	}
	if InspectBody([]byte(`{"nested":["\u003cscript\u003e"]}`)) != "XSS" {
		t.Fatal("JSON normalization")
	}
}
func TestPublicIP(t *testing.T) {
	for _, s := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "::1", "::ffff:127.0.0.1", "fc00::1", "fe80::1", "ff02::1", "100.64.0.1", "192.0.2.1", "64:ff9b::a00:1", "0.0.0.0", "198.18.0.1"} {
		if PublicIP(netip.MustParseAddr(s)) {
			t.Errorf("allowed %s", s)
		}
	}
	for _, s := range []string{"1.1.1.1", "2606:4700::1111"} {
		if !PublicIP(netip.MustParseAddr(s)) {
			t.Errorf("blocked %s", s)
		}
	}
}
func TestHost(t *testing.T) {
	a := map[string]bool{"demo.aegis.test": true}
	if h, e := Host("DEMO.AEGIS.TEST.", a); e != nil || h != "demo.aegis.test" {
		t.Fatal(h, e)
	}
	for _, s := range []string{"127.0.0.1", "169.254.169.254", "https://demo.aegis.test", "demo.aegis.test:443", "other.example", "demo.aegis.test@other.example"} {
		if _, e := Host(s, a); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
}
