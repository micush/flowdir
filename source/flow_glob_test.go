package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"testing"
	"time"
)

func TestGlobMatchAndIPv4Wildcards(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"*.cox.net", "ip1.wan.cox.net", true}, {"*.cox.net", "COX.NET", false}, {"*.cox.net", "cox.net.evil.com", false},
		{"*.COX.net", "a.cox.NET", true}, {"10.*.1.1", "10.9.1.1", true}, {"10.*.1.1", "10.9.1.2", false},
		{"2001:db8:*", "2001:db8::1", true}, {"2001:db8:*", "2001:db9::1", false}, {"*", "anything", true}, {"a*b*c", "aXbYc", true}, {"a*b*c", "aXbY", false},
	} {
		if got := globMatch(c.p, c.s); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v", c.p, c.s, got)
		}
	}
	for p, want := range map[string]string{"10.1.1.*": "10.1.1.0/24", "10.1.*.*": "10.1.0.0/16", "10.*": "10.0.0.0/8", "10.*.*.*": "10.0.0.0/8", "*": "0.0.0.0/0", "192.168.*": "192.168.0.0/16"} {
		got, ok := ipv4Wildcard(p)
		if !ok || got.String() != want {
			t.Errorf("ipv4Wildcard(%q) = %v %v, want %s", p, got, ok, want)
		}
	}
	for _, p := range []string{"10.*.1.1", "10.1.1.1", "300.*", "a.*", "10..*", "10.1.1.1.*", "*.cox.net", "2001:db8:*"} {
		if got, ok := ipv4Wildcard(p); ok {
			t.Errorf("ipv4Wildcard(%q) = %v: not a trailing-star IPv4 pattern", p, got)
		}
	}
	for p, want := range map[string]bool{"*.cox.net": true, "cox*": true, "10.*.1.1": false, "2001:db8:*": false, "fe80::*": false, "abc.*": true, "10.1.*": false} {
		if globNeedsDNS(p) != want {
			t.Errorf("globNeedsDNS(%q) = %v", p, !want)
		}
	}
}

func TestFlowFilterWildcards(t *testing.T) {
	s := newTestFlowSvc()
	s.store.resolve = func(as []netip.Addr, _ time.Duration) map[netip.Addr]string {
		n := map[string]string{"203.0.113.9": "ip9.wan.cox.net", "198.51.100.1": "mail.example.org", "8.8.8.8": "dns.google"}
		out := map[netip.Addr]string{}
		for _, a := range as {
			if v := n[a.String()]; v != "" {
				out[a] = v
			}
		}
		return out
	}
	at := time.Now().Add(-2 * time.Minute)
	add := func(src, dst string, dport uint16, b uint64) { s.store.Add(rec(src, dst, 50000, dport, 6, b, at)) }
	add("10.1.1.1", "203.0.113.9", 443, 1000)
	add("10.1.2.2", "203.0.113.9", 443, 4000)
	add("10.2.3.3", "198.51.100.1", 22, 30000)
	add("10.1.1.7", "8.8.8.8", 53, 200000)
	add("2001:db8::5", "2001:db8::6", 80, 7000000)
	total := func(expr string) uint64 {
		q, err := s.parseFlowQuery(url.Values{"filter": {expr}, "range": {"15m"}}, false)
		if err != nil {
			t.Fatalf("%q: %v", expr, err)
		}
		b, _ := json.Marshal(q) // the trip to a peer
		var q2 FlowQuery
		if err := json.Unmarshal(b, &q2); err != nil || q2.Validate() != nil {
			t.Fatalf("%q: lost on the wire: %v %v", expr, err, q2.Validate())
		}
		return s.store.Query(q2).Total.Bytes
	}
	for _, c := range []struct {
		expr string
		want uint64
	}{
		{"10.1.1.*", 201000}, {"10.1.*.*", 205000}, {"10.1.*", 205000}, {"10.*", 235000},
		{"10.*.1.1", 1000}, // a star in the middle: matched against the address text
		{"*.cox.net", 5000}, {"host=*.cox.net", 5000}, {"dst=*.cox.net", 5000}, {"src=*.cox.net", 0},
		{"*.cox.net AND 10.1.1.*", 1000}, {"!*.cox.net", 7230000}, {"*.google OR *.example.org", 230000},
		{"2001:db8:*", 7000000}, {"*.nomatch.invalid", 0}, {"host=10.2.3.3,*.cox.net", 35000},
	} {
		if got := total(c.expr); got != c.want {
			t.Errorf("%q: %d bytes, want %d", c.expr, got, c.want)
		}
	}
	// the tree of a query is not changed by running it (a peer's copy and the asker's are the same object in the tests)
	q, _ := s.parseFlowQuery(url.Values{"filter": {"*.cox.net OR 443"}, "range": {"15m"}}, false)
	s.store.Query(q)
	if !q.Filter.Expr.hasGlobs() {
		t.Error("running a query replaced the wildcards in the caller's filter")
	}
}

func TestHourlyHistoryIsKeptUntilTheDiskCapAndAllRange(t *testing.T) {
	s := newTestFlowSvc()
	now := time.Now()
	old := now.Add(-40 * 24 * time.Hour).Truncate(time.Hour).Unix() // far beyond the old 7 days
	s.store.mu.Lock()
	s.store.hour[old] = &flowBucket{TS: old, M: map[flowKey]flowVal{{Exp: tExp, Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2")}: {5000, 5, 1}}}
	s.store.mu.Unlock()
	s.store.Maintain()
	if s.store.oldest() != old {
		t.Fatalf("a 40 day old hour was dropped with no time limit set (oldest %d, want %d)", s.store.oldest(), old)
	}
	q, err := s.parseFlowQuery(url.Values{"range": {"all"}}, false)
	if err != nil || q.From != old {
		t.Fatalf("range=all: from %d (%v), want %d", q.From, err, old)
	}
	if a := s.store.Query(q); a.Total.Bytes != 5000 {
		t.Errorf("range=all found %d bytes, want 5000", a.Total.Bytes)
	}
	// the node reports its oldest bucket in its status, which is how the asking node finds the oldest of the whole cluster
	if st := s.Status(); st.Oldest != old {
		t.Errorf("status oldest %d, want %d", st.Oldest, old)
	}
	if got := s.oldestAll(); got != old {
		t.Errorf("oldestAll with no other node: %d, want %d", got, old)
	}
	if q, err = s.parseFlowQuery(url.Values{"range": {"90d"}}, false); err != nil || q.Validate() != nil {
		t.Errorf("range=90d: %v %v", err, q.Validate())
	}
	if q, err = s.parseFlowQuery(url.Values{"range": {"1y"}}, false); err != nil || q.Validate() != nil {
		t.Errorf("range=1y: %v %v", err, q.Validate())
	}
	// an explicit limit still works
	s.store.SetConfig(FlowConfig{HourDays: 7})
	s.store.Maintain()
	if s.store.oldest() == old {
		t.Error("hour_days=7 did not drop a 40 day old hour")
	}
}

func TestDiskCapDropsTheHourFromTheReports(t *testing.T) {
	dir := t.TempDir()
	s := testStore(dir)
	s.volSize = func(string) (uint64, error) { return 1_000_000, nil }
	s.SetCap(0, 1) // 1 MB
	h1, h2 := tNow.Add(-5*time.Hour).Truncate(time.Hour).Unix(), tNow.Add(-4*time.Hour).Truncate(time.Hour).Unix()
	for _, h := range []int64{h1, h2} {
		s.hour[h] = &flowBucket{TS: h, M: map[flowKey]flowVal{}}
		seedFlowFile(t, dir, fmt.Sprintf("h-%d.gob", h), 700_000)
	}
	s.mu.Lock()
	s.enforceCapLocked(tNow)
	s.mu.Unlock()
	if s.hour[h1] != nil || s.hour[h2] == nil {
		t.Errorf("after the cap removed the oldest file: oldest hour in memory %v, newer %v", s.hour[h1] != nil, s.hour[h2] != nil)
	}
}
