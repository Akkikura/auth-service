package httpapi

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

type ClientIPResolver struct {
	trusted []netip.Prefix
}

func NewClientIPResolver(cidrs []string) (*ClientIPResolver, error) {
	resolver := &ClientIPResolver{trusted: make([]netip.Prefix, 0, len(cidrs))}
	for _, raw := range cidrs {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		resolver.trusted = append(resolver.trusted, prefix.Masked())
	}
	return resolver, nil
}

func (r *ClientIPResolver) Resolve(request *http.Request) string {
	remote, ok := parseRemoteIP(request.RemoteAddr)
	if !ok {
		return request.RemoteAddr
	}
	if r == nil || !r.isTrusted(remote) {
		return remote.String()
	}

	// TODO справа налево потому что справа мой прокси
	forwarded := strings.Split(request.Header.Get("X-Forwarded-For"), ",")
	for index := len(forwarded) - 1; index >= 0; index-- {
		candidate, err := netip.ParseAddr(strings.TrimSpace(forwarded[index]))
		if err != nil {
			continue
		}
		candidate = candidate.Unmap()
		if !r.isTrusted(candidate) {
			return candidate.String()
		}
	}

	if candidate, err := netip.ParseAddr(strings.TrimSpace(request.Header.Get("X-Real-IP"))); err == nil {
		candidate = candidate.Unmap()
		if !r.isTrusted(candidate) {
			return candidate.String()
		}
	}
	return remote.String()
}

func (r *ClientIPResolver) isTrusted(address netip.Addr) bool {
	address = address.Unmap()
	for _, prefix := range r.trusted {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func parseRemoteIP(remoteAddress string) (netip.Addr, bool) {
	if address, err := netip.ParseAddrPort(remoteAddress); err == nil {
		return address.Addr().Unmap(), true
	}
	if host, _, err := net.SplitHostPort(remoteAddress); err == nil {
		if address, err := netip.ParseAddr(host); err == nil {
			return address.Unmap(), true
		}
	}
	if address, err := netip.ParseAddr(remoteAddress); err == nil {
		return address.Unmap(), true
	}
	return netip.Addr{}, false
}
