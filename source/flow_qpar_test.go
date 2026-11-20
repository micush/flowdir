package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"runtime"
	"testing"
	"time"
)

// fillHours puts n hour buckets of keysPer keys each in the store, from a base far in the past.
func fillHours(s *flowStore, n, keysPer int) (from, to int64) { return fillHoursExp(s, n, keysPer, 1) }

func fillHoursExp(s *flowStore, n, keysPer, nexp int) (from, to int64) {
	base := time.Now().Add(-time.Duration(n+2) * time.Hour).Truncate(time.Hour).Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	for h := 0; h < n; h++ {
		ts := base + int64(h)*3600
		b := &flowBucket{TS: ts, M: map[flowKey]flowVal{}, Other: flowVal{7, 1, 1}}
		for i := 0; i < keysPer; i++ {
			k := flowKey{Exp: netip.AddrFrom4([4]byte{192, 0, 2, byte(1 + i%nexp)}), SrcAS: uint32(i % 5), DstAS: uint32(i % 3), InIf: uint32(i % 4), OutIf: uint32(i % 3), Src: netip.AddrFrom4([4]byte{10, byte(i % 7), byte(i >> 8), byte(i)}), Dst: netip.AddrFrom4([4]byte{198, 51, 100, byte(i % 40)}),
				SPort: uint16(1024 + i%100), DPort: uint16(80 + i%3), Proto: 6}
			b.M[k] = flowVal{uint64(100 + i + h), uint64(1 + i%5), 1}
		}
		s.hour[ts] = b
		s.idxSet(ts, buildIdx(b))
	}
	return base, base + int64(n)*3600
}

func TestParallelQueryEqualsSerial(t *testing.T) {
	if runtime.GOMAXPROCS(0) < 2 {
		runtime.GOMAXPROCS(4)
		defer runtime.GOMAXPROCS(1)
	}
	s := newTestFlowSvc().store
	from, to := fillHours(s, 12, 4000) // 48000 keys: over the parallel threshold
	for _, by := range []string{"", "service", "conversation", "host", "dst", "src", "exporter", "protocol", "src_as", "dst_as", "flow", "interface"} {
		for _, step := range []int{0, 3600} {
			q := FlowQuery{From: from, To: to, By: by, Step: step, NoDedupe: true, Limit: 50}
			par := s.Query(q)
			qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
			serial := serialQuery(s, q)
			if !reflect.DeepEqual(par, serial) {
				pj, _ := json.Marshal(par)
				sj, _ := json.Marshal(serial)
				t.Errorf("by=%q step=%d: parallel answer differs from the serial one\n%.300s\n%.300s", by, step, pj, sj)
			}
		}
	}
	// the digest too
	d1 := s.Digest(FlowQuery{From: from, To: to})
	if len(d1.Ents) == 0 {
		t.Fatal("no digest")
	}
	var b, p uint64
	for _, e := range d1.Ents {
		b += e.B
		p += e.P
	}
	var wantB uint64
	s.mu.RLock()
	for _, r := range func() []bucketRef { r, _, _ := s.bucketsLocked(from, to); return r }() {
		for _, v := range r.b.M {
			wantB += v.Bytes
		}
	}
	s.mu.RUnlock()
	if b != wantB {
		t.Errorf("digest adds up to %d bytes, want %d", b, wantB)
	}
}

// serialQuery answers q on one goroutine and without the cache.
func serialQuery(s *flowStore, q FlowQuery) FlowAnswer {
	old := qcache
	qcache = nil
	defer func() { qcache = old }()
	prev := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(prev)
	return s.Query(q)
}

func TestHourlyCacheHitsAndInvalidates(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	s := newTestFlowSvc().store
	from, to := fillHours(s, 6, 3000)
	q := FlowQuery{From: from, To: to, By: "service", NoDedupe: true, Limit: 20}
	a1 := s.Query(q)
	if qcache.hits.Load() != 0 || len(qcache.m) == 0 {
		t.Fatalf("first run: hits %d, entries %d (a service grouping is small: it should be cached)", qcache.hits.Load(), len(qcache.m))
	}
	a2 := s.Query(q)
	if qcache.hits.Load() != 6 {
		t.Errorf("second run: %d hits, want 6", qcache.hits.Load())
	}
	if !reflect.DeepEqual(a1, a2) {
		t.Error("a cached answer differs from the computed one")
	}
	if want := serialQuery(s, q); !reflect.DeepEqual(a2, want) {
		t.Error("a cached answer differs from the serial, uncached one")
	}
	// a bucket that changed (a different key count) is not taken from the cache
	s.mu.Lock()
	b := s.hour[from]
	b.M[flowKey{Exp: netip.MustParseAddr("192.0.2.1"), Src: netip.MustParseAddr("10.200.0.1"), Dst: netip.MustParseAddr("198.51.100.1"), SPort: 1, DPort: 443, Proto: 6}] = flowVal{999999, 1, 1}
	s.mu.Unlock()
	a3 := s.Query(q)
	if a3.Total.Bytes != a2.Total.Bytes+999999 {
		t.Errorf("a changed hour: total %d, want %d", a3.Total.Bytes, a2.Total.Bytes+999999)
	}
	// another filter, grouping or set of losers is another entry
	n := len(qcache.m)
	q2 := q
	q2.Filter = FlowFilter{Ports: []uint16{80}}
	if r := s.Query(q2); r.Total.Bytes >= a3.Total.Bytes || r.Total.Bytes == 0 {
		t.Errorf("filtered total %d vs %d", r.Total.Bytes, a3.Total.Bytes)
	}
	q3 := q
	q3.NoDedupe = false
	q3.Losers = []flowLoser{{H: 1, Exp: netip.MustParseAddr("192.0.2.1")}}
	s.Query(q3)
	if len(qcache.m) <= n {
		t.Errorf("a different filter or losers set did not make new entries (%d, was %d)", len(qcache.m), n)
	}
	k1, k2 := qcache.keyFor(&q, false), qcache.keyFor(&q3, false)
	if *k1 == *k2 {
		t.Error("losers are not part of the cache key")
	}
	l := []flowLoser{{1, netip.MustParseAddr("192.0.2.1")}, {2, netip.MustParseAddr("192.0.2.2")}}
	ra, rb := q, q
	ra.Losers = l
	rb.Losers = []flowLoser{l[1], l[0]}
	if *qcache.keyFor(&ra, false) != *qcache.keyFor(&rb, false) {
		t.Error("the order of the losers changes the cache key")
	}
}

func TestCacheStaysWithinItsBudget(t *testing.T) {
	c := &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	k := &qcacheKey{by: "service"}
	for i := 0; i < 200; i++ {
		a := newQAcc(0)
		for g := 0; g < 5000; g++ {
			a.groups[groupKey{P1: uint16(g), If: uint32(i)}] = flowVal{1, 1, 1}
		}
		b := &flowBucket{TS: int64(i) * 3600, M: make(map[flowKey]flowVal, 20000)}
		for j := 0; j < 20000; j++ {
			b.M[flowKey{SPort: uint16(j), InIf: uint32(j)}] = flowVal{}
		}
		c.put(k, b.TS, uint64(i), len(b.M), a)
	}
	if c.groups > c.budget {
		t.Errorf("cache holds %d groups, budget %d", c.groups, c.budget)
	}
	if len(c.m) == 0 {
		t.Error("cache is empty")
	}
}

func TestRangeScaledTimeouts(t *testing.T) {
	h := int64(3600)
	for _, c := range []struct {
		span int64
		want time.Duration
	}{{h, 10 * time.Second}, {6 * h, 10 * time.Second}, {24 * h, 30 * time.Second}, {7 * 24 * h, 30 * time.Second}, {30 * 24 * h, 100 * time.Second}} {
		if got := flowRoundTimeout(1000, 1000+c.span); got != c.want {
			t.Errorf("round timeout for %ds = %v, want %v", c.span, got, c.want)
		}
	}
	if d := flowReportTimeout(FlowQuery{From: 0, To: 3600}); d != 30*time.Second {
		t.Errorf("short report timeout %v, want the old 30s", d)
	}
	if d := flowReportTimeout(FlowQuery{From: 0, To: 90 * 86400}); d != 210*time.Second {
		t.Errorf("long report timeout %v", d)
	}
}

// groupsByBrute adds up a grouping the slow way, with emit, for the answer to be checked against.
func groupsByBrute(s *flowStore, q FlowQuery) (rows map[string]flowVal, total flowVal) {
	rows = map[string]flowVal{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	refs, _, _ := s.bucketsLocked(q.From, q.To)
	for _, r := range refs {
		for k, v := range r.b.M {
			if !q.Filter.empty() && !q.Filter.match(k) {
				continue
			}
			total.add(v)
			emit(q.By, k, func(g groupKey) {
				id := fmt.Sprint(g.dims(q.By))
				c := rows[id]
				c.add(v)
				rows[id] = c
			})
		}
		total.add(r.b.Other)
	}
	return
}

func TestCompactGroupMapsMatchTheGeneralOne(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	s := newTestFlowSvc().store
	from, to := fillHoursExp(s, 5, 900, 3)
	for _, by := range []string{"host", "src", "dst", "exporter", "conversation", "service", "protocol", "src_as", "dst_as", "flow", "interface"} {
		q := FlowQuery{From: from, To: to, By: by, NoDedupe: true, Limit: 1000}
		a := s.Query(q)
		want, _ := groupsByBrute(s, q)
		if len(a.Rows) != len(want) && !a.Cut {
			t.Errorf("by=%s: %d rows, want %d", by, len(a.Rows), len(want))
		}
		for _, r := range a.Rows {
			id := fmt.Sprint(r.Key)
			if w := want[id]; w.Bytes != r.Bytes || w.Packets != r.Packets || w.Flows != r.Flows {
				t.Errorf("by=%s %s: got %d/%d/%d, want %d/%d/%d", by, id, r.Bytes, r.Packets, r.Flows, w.Bytes, w.Packets, w.Flows)
				break
			}
		}
	}
}

func TestIndexLeavesOutHoursThatCannotMatch(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	s := newTestFlowSvc().store
	from, to := fillHoursExp(s, 6, 600, 2)
	// make hour 3 the only one with exporter .9 and port 9999
	s.mu.Lock()
	ts := from + 3*3600
	hb := s.hour[ts]
	k := flowKey{Exp: netip.MustParseAddr("192.0.2.9"), Src: netip.MustParseAddr("10.9.9.9"), Dst: netip.MustParseAddr("198.51.100.9"), SPort: 40000, DPort: 9999, Proto: 17}
	hb.M[k] = flowVal{12345, 3, 1}
	s.idxSet(ts, buildIdx(hb))
	s.mu.Unlock()
	for _, f := range []FlowFilter{
		{Exporters: []netip.Prefix{netip.MustParsePrefix("192.0.2.9/32")}},
		{Ports: []uint16{9999}},
		{Protos: []uint8{17}},
	} {
		q := FlowQuery{From: from, To: to, By: "service", NoDedupe: true, Filter: f}
		s.mu.RLock()
		refs, _, _ := s.bucketsLocked(from, to)
		kept := pruneRefs(refs, &q.Filter)
		s.mu.RUnlock()
		if len(refs) != 6 || len(kept) != 1 || kept[0].ts != ts {
			t.Errorf("filter %+v: %d of %d hours kept, want only the third", f, len(kept), len(refs))
		}
		if a := s.Query(q); a.Total.Bytes != 12345 {
			t.Errorf("filter %+v: total %d, want 12345", f, a.Total.Bytes)
		}
	}
	// a filter every hour can match leaves all of them
	s.mu.RLock()
	refs, _, _ := s.bucketsLocked(from, to)
	n := len(pruneRefs(refs, &FlowFilter{Ports: []uint16{80}}))
	s.mu.RUnlock()
	if n != 6 {
		t.Errorf("port 80 is in every hour: %d kept", n)
	}
}

func TestBiggestGroupsOfLongRangesAreStableAndMarked(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	s := newTestFlowSvc().store
	from, to := fillHours(s, 30, 12000) // 30 hours: over truncMinHours
	// one dominant host in every hour
	s.mu.Lock()
	for ts, b := range s.hour {
		b.M[flowKey{Exp: netip.MustParseAddr("192.0.2.1"), Src: netip.MustParseAddr("10.99.99.99"), Dst: netip.MustParseAddr("198.51.100.1"), DPort: 443, Proto: 6}] = flowVal{1 << 40, 1 << 20, 1}
		s.idxSet(ts, buildIdx(b))
	}
	s.mu.Unlock()
	q := FlowQuery{From: from, To: to, By: "host", NoDedupe: true, Limit: 5}
	a1 := s.Query(q)
	a2 := s.Query(q) // from the cache
	if !a1.Approx || !a2.Approx {
		t.Errorf("a long host report is not marked approximate: %v %v", a1.Approx, a2.Approx)
	}
	if !reflect.DeepEqual(a1, a2) {
		t.Error("the first run and the cached run of a long host report differ")
	}
	if len(a1.Rows) == 0 || a1.Rows[0].Key["host"] != "10.99.99.99" && a1.Rows[0].Key["host"] != "198.51.100.1" {
		t.Errorf("the dominant host is not first: %+v", a1.Rows[:1])
	}
	if qcache.hits.Load() < 30 {
		t.Errorf("second run: %d cache hits, want 30", qcache.hits.Load())
	}
	// a short range stays exact
	sh := FlowQuery{From: from, To: from + 3*3600, By: "host", NoDedupe: true, Limit: 5}
	if a := s.Query(sh); a.Approx {
		t.Error("a 3 hour host report is approximate")
	}
	// the totals are exact either way
	if _, want := groupsByBrute(s, q); a1.Total.Bytes != want.Bytes {
		t.Errorf("total %d, want %d", a1.Total.Bytes, want.Bytes)
	}
}

func TestHoursOnlyOnDiskAreReported(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	s := newTestFlowSvc().store
	from, to := fillHoursExp(s, 6, 800, 2)
	dir := t.TempDir()
	s.mu.Lock()
	s.diskHours = map[int64]string{}
	for ts, b := range s.hour {
		p := fmt.Sprintf("%s/h-%d.gob", dir, ts)
		if err := writeGobFile(p, bucketRec(b)); err != nil {
			t.Fatal(err)
		}
		s.diskHours[ts] = p
	}
	s.mu.Unlock()
	q := FlowQuery{From: from, To: to, By: "service", NoDedupe: true, Limit: 100}
	want := s.Query(q)
	// the memory cap pushes four hours out of memory
	s.mu.Lock()
	for i := 0; i < 4; i++ {
		ts := from + int64(i)*3600
		delete(s.hour, ts)
	}
	s.idxMu.Lock()
	for i := 0; i < 4; i++ {
		delete(s.idx, from+int64(i)*3600)
	}
	s.idxMu.Unlock()
	s.mu.Unlock()
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	got := s.Query(q)
	if !reflect.DeepEqual(got.Rows, want.Rows) || got.Total.Bytes != want.Total.Bytes {
		t.Errorf("with four hours on disk the report differs: total %d, want %d", got.Total.Bytes, want.Total.Bytes)
	}
	if s.idxGet(from) == nil {
		t.Error("the index of an hour read from disk is not kept")
	}
	h := qcache.hits.Load()
	if again := s.Query(q); !reflect.DeepEqual(again.Rows, want.Rows) || qcache.hits.Load()-h != 6 {
		t.Errorf("the second report read the files again: %d hits", qcache.hits.Load()-h)
	}
	// a high-cardinality report and the digest read them too
	if a := s.Query(FlowQuery{From: from, To: to, By: "host", NoDedupe: true, Limit: 1000}); a.Total.Bytes != want.Total.Bytes {
		t.Errorf("host report total %d, want %d", a.Total.Bytes, want.Total.Bytes)
	}
	d := s.Digest(FlowQuery{From: from, To: to})
	var b uint64
	for _, e := range d.Ents {
		b += e.B
	}
	if b == 0 || b > want.Total.Bytes {
		t.Errorf("digest over hours on disk adds up to %d (report total %d)", b, want.Total.Bytes)
	}
	if o := s.oldest(); o != from {
		t.Errorf("oldest %d, want %d", o, from)
	}
}

func TestRangeExporters(t *testing.T) {
	s := newTestFlowSvc().store
	from, to := fillHoursExp(s, 3, 200, 1)
	if e := s.rangeExporters(FlowQuery{From: from, To: to}); len(e.Addrs) != 1 || e.Unknown {
		t.Errorf("one exporter: %+v", e)
	}
	from, to = fillHoursExp(newTestFlowSvc().store, 3, 200, 2)
	s2 := newTestFlowSvc().store
	from, to = fillHoursExp(s2, 3, 200, 2)
	if e := s2.rangeExporters(FlowQuery{From: from, To: to}); len(e.Addrs) != 2 {
		t.Errorf("two exporters: %+v", e)
	}
	s2.mu.Lock()
	s2.diskHours = map[int64]string{from - 3600: "/nonexistent/h"}
	s2.mu.Unlock()
	if e := s2.rangeExporters(FlowQuery{From: from - 3600, To: to}); !e.Unknown && len(e.Addrs) < 2 {
		t.Errorf("an hour that is not known: %+v", e)
	}
}

func TestRealHistoryWithAMemoryCapLeavesOlderHoursOnDisk(t *testing.T) {
	qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: 400000}
	dir := t.TempDir()
	s := testStore(dir)
	for h := 2; h <= 5; h++ {
		at := tNow.Add(-time.Duration(h) * time.Hour)
		for p := uint16(40000); p < 40020; p++ {
			s.Add(rec("10.0.0.5", "203.0.113.9", p, 443, 6, uint64(1000*h), at))
		}
	}
	s.Maintain()
	s.flushAll()
	q := FlowQuery{From: tNow.Add(-6 * time.Hour).Unix(), To: tNow.Unix(), By: "service", NoDedupe: true}
	want := s.Query(q)
	if want.Total.Bytes == 0 || len(s.hour) < 4 {
		t.Fatalf("setup: total %d, %d hours", want.Total.Bytes, len(s.hour))
	}
	s.Close()
	s2 := testStore(dir)
	s2.memTotal = func() uint64 { return 1500 } // room for about one bucket
	s2.SetMemCap(0, 0)
	s2.Load()
	if len(s2.diskHours) < 4 || len(s2.hour) >= 4 {
		t.Fatalf("setup: %d hourly files, %d hours in memory", len(s2.diskHours), len(s2.hour))
	}
	got := s2.Query(q)
	if got.Total.Bytes != want.Total.Bytes {
		t.Errorf("with the older hours on disk the total is %d, want %d", got.Total.Bytes, want.Total.Bytes)
	}
	if s2.oldest() > tNow.Add(-5*time.Hour).Unix()/3600*3600 {
		t.Errorf("oldest %d does not reach the hours on disk", s2.oldest())
	}
}
