package httpapi

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPResolverIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "203.0.113.20:1234"
	request.Header.Set("X-Forwarded-For", "198.51.100.5")
	if got := resolver.Resolve(request); got != "203.0.113.20" {
		t.Fatalf("expected peer IP, got %q", got)
	}
}

func TestClientIPResolverWalksTrustedProxyChainFromRight(t *testing.T) {
	resolver, err := NewClientIPResolver([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/", nil)
	request.RemoteAddr = "10.0.0.3:1234"
	request.Header.Set("X-Forwarded-For", "192.0.2.55, 198.51.100.8, 10.0.0.2")
	if got := resolver.Resolve(request); got != "198.51.100.8" {
		t.Fatalf("expected nearest untrusted address, got %q", got)
	}
}

func TestClientIPResolverRejectsInvalidCIDR(t *testing.T) {
	if _, err := NewClientIPResolver([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}
