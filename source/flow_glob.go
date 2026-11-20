package main

// Wildcards in the Flow filter:  10.1.1.*  is the subnet 10.1.1.0/24,  10.1.*.*  is 10.1.0.0/16,  *.cox.net  is every host whose
// DNS name ends in .cox.net,  2001:db8:*  is every address that starts that way.
//
// An IPv4 pattern whose stars are all at the end is turned into a prefix when the filter is read: nothing to resolve, nothing
// to store.  Anything else (a star in the middle of an address, an IPv6 pattern, a name) is kept as a pattern in the term and is
// turned into addresses by the node that runs the query (expandGlobs): it takes the addresses its rollups hold for the range,
// looks the names up (the cache of reverse names the reports already use) and keeps those that match.

import (
	"net/netip"
	"sort"
	"strings"
	"time"
)

// globMatch reports whether s matches pattern, where * stands for any run of characters (dots included); case is ignored.
func globMatch(pattern, s string) bool {
	p, t := strings.ToLower(pattern), strings.ToLower(s)
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case pi < len(p) && p[pi] == t[ti]:
			pi++
			ti++
		case star >= 0:
			mark++
			pi, ti = star+1, mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// ipv4Wildcard turns 10.1.1.*  or  10.1.*.*  or  10.*  into a prefix; ok is false when the stars are not all at the end.
func ipv4Wildcard(p string) (netip.Prefix, bool) {
	parts := strings.Split(p, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Prefix{}, false
	}
	var oct [4]byte
	n := 0
	for i, e := range parts {
		if e == "*" {
			for _, r := range parts[i:] {
				if r != "*" {
					return netip.Prefix{}, false
				}
			}
			break
		}
		v := 0
		if e == "" || len(e) > 3 {
			return netip.Prefix{}, false
		}
		for _, c := range e {
			if c < '0' || c > '9' {
				return netip.Prefix{}, false
			}
			v = v*10 + int(c-'0')
		}
		if v > 255 {
			return netip.Prefix{}, false
		}
		oct[i] = byte(v)
		n++
	}
	if n == 4 || n == 0 && len(parts) == 1 && parts[0] != "*" {
		return netip.Prefix{}, false // no star, or not a pattern
	}
	return netip.PrefixFrom(netip.AddrFrom4(oct), 8*n), true
}

// globNeedsDNS: a pattern of digits, dots and stars (IPv4), or of hex digits, colons, dots and stars with a colon (IPv6), is matched
// against the address; any other is a name.
func globNeedsDNS(p string) bool {
	v4, v6 := true, strings.Contains(p, ":")
	for _, c := range p {
		if !(c >= '0' && c <= '9' || c == '.' || c == '*') {
			v4 = false
		}
		if !(c >= '0' && c <= '9' || c == '.' || c == '*' || c == ':' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			v6 = false
		}
	}
	return !v4 && !v6
}

// splitGlobs separates the wildcard entries of a list from the rest; the wildcards that are an IPv4 prefix come back as prefixes.
func splitGlobs(list []string) (plain []string, prefixes []netip.Prefix, globs []string) {
	for _, e := range list {
		if !strings.Contains(e, "*") {
			plain = append(plain, e)
		} else if p, ok := ipv4Wildcard(e); ok {
			prefixes = append(prefixes, p)
		} else {
			globs = append(globs, e)
		}
	}
	return
}

// neverPrefix matches nothing a flow carries: what a pattern that matched no address expands to (an empty list would match all).
var neverPrefix = netip.PrefixFrom(netip.IPv4Unspecified(), 32)

func (f *FlowFilter) hasGlobs() bool {
	return len(f.HostGlobs)+len(f.SrcGlobs)+len(f.DstGlobs) > 0
}

func (e *FlowExpr) hasGlobs() bool {
	if e == nil {
		return false
	}
	if e.Term != nil && e.Term.hasGlobs() {
		return true
	}
	for _, k := range e.Kids {
		if k.hasGlobs() {
			return true
		}
	}
	return false
}

func (e *FlowExpr) collectGlobs(dns *bool) {
	if e == nil {
		return
	}
	if e.Term != nil {
		for _, l := range [][]string{e.Term.HostGlobs, e.Term.SrcGlobs, e.Term.DstGlobs} {
			for _, g := range l {
				if globNeedsDNS(g) {
					*dns = true
				}
			}
		}
	}
	for _, k := range e.Kids {
		k.collectGlobs(dns)
	}
}

// expandGlobs returns q with every wildcard replaced by the addresses (of this node's rollups for the range) that match it.
// The tree of q is not changed: it may be one the caller shares.
func (s *flowStore) expandGlobs(q FlowQuery) FlowQuery {
	if !q.Filter.hasGlobs() && !q.Filter.Expr.hasGlobs() {
		return q
	}
	needDNS := false
	for _, l := range [][]string{q.Filter.HostGlobs, q.Filter.SrcGlobs, q.Filter.DstGlobs} {
		for _, g := range l {
			if globNeedsDNS(g) {
				needDNS = true
			}
		}
	}
	q.Filter.Expr.collectGlobs(&needDNS)
	// the addresses this node saw in the range, the busiest first
	sum := map[netip.Addr]uint64{}
	s.mu.RLock()
	refs, _, _ := s.bucketsLocked(q.From, q.To)
	for _, r := range refs {
		if r.b == nil { // a cold hour: only what is in memory is looked at for names
			continue
		}
		for k, v := range r.b.M {
			if k.Src.IsValid() {
				sum[k.Src] += v.Bytes
				sum[k.Dst] += v.Bytes
			}
		}
	}
	s.mu.RUnlock()
	addrs := make([]netip.Addr, 0, len(sum))
	for a := range sum {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return sum[addrs[i]] > sum[addrs[j]] })
	if len(addrs) > flowGlobMaxAddrs {
		addrs = addrs[:flowGlobMaxAddrs]
	}
	var names map[netip.Addr]string
	if needDNS && s.resolve != nil {
		names = s.resolve(addrs, flowGlobBudget)
	}
	match := func(globs []string) []netip.Prefix {
		var out []netip.Prefix
		for _, a := range addrs {
			for _, g := range globs {
				if globMatch(g, a.String()) || (globNeedsDNS(g) && names[a] != "" && globMatch(g, names[a])) {
					out = append(out, netip.PrefixFrom(a, a.BitLen()))
					break
				}
			}
		}
		if len(out) == 0 {
			out = []netip.Prefix{neverPrefix}
		}
		return out
	}
	var expand func(f FlowFilter) FlowFilter
	expand = func(f FlowFilter) FlowFilter {
		if len(f.HostGlobs) > 0 {
			f.Hosts = append(append([]netip.Prefix(nil), f.Hosts...), match(f.HostGlobs)...)
			f.HostGlobs = nil
		}
		if len(f.SrcGlobs) > 0 {
			f.Src = append(append([]netip.Prefix(nil), f.Src...), match(f.SrcGlobs)...)
			f.SrcGlobs = nil
		}
		if len(f.DstGlobs) > 0 {
			f.Dst = append(append([]netip.Prefix(nil), f.Dst...), match(f.DstGlobs)...)
			f.DstGlobs = nil
		}
		return f
	}
	var walk func(e *FlowExpr) *FlowExpr
	walk = func(e *FlowExpr) *FlowExpr {
		if e == nil {
			return nil
		}
		c := *e
		if e.Term != nil {
			t := expand(*e.Term)
			c.Term = &t
		}
		c.Kids = nil
		for _, k := range e.Kids {
			c.Kids = append(c.Kids, walk(k))
		}
		return &c
	}
	q.Filter = expand(q.Filter)
	q.Filter.Expr = walk(q.Filter.Expr)
	return q
}

// how many addresses a wildcard is tried against, and how long the name lookups may take in all
const flowGlobMaxAddrs = 4000

var flowGlobBudget = 4 * time.Second
