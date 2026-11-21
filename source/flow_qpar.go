package main

// Parallel, indexed and cached evaluation of flow queries.
//
// A report is a sum over buckets, so it splits across cores: every worker takes buckets, adds them into an accumulator of its
// own, and the accumulators are added up at the end.  Additions commute, so the answer is the same as the serial one.
//
// An hourly bucket is made once and never changes.  That allows four things:
//   - an index of what an hour holds (exporters, ports, protocols) lets a report that filters on them skip the hours that cannot match;
//   - what a query takes from an hour (its totals and groups, for one filter, one grouping and one set of deduplication losers) is
//     cached, and the common groupings of every new hour are put in the cache as the hour is made;
//   - for the groupings with a group for about every key (host, conversation, flow) the cache keeps each hour's biggest groups only,
//     and a report over a day or more always uses those, so the first and the later runs agree (the answer says it is approximate);
//   - an hour the memory cap left out of memory is read from its file when a report asks for it, and its index and cache entries
//     are kept, so the next report does not read it again.

import (
	"encoding/json"
	"hash/fnv"
	"net/netip"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// parallelMinKeys is the number of keys below which a query is not worth splitting across goroutines.
const parallelMinKeys = 20000

const (
	byNone = iota
	byHost
	bySrc
	byDst
	byExporter
	byConv
	byService
	byProtocol
	bySrcAS
	byDstAS
)

// byKind says which of the compact maps (not the general groupKey one) a grouping is counted in.
func byKind(by string) int {
	switch by {
	case "host":
		return byHost
	case "src":
		return bySrc
	case "dst":
		return byDst
	case "exporter":
		return byExporter
	case "conversation":
		return byConv
	case "service":
		return byService
	case "protocol":
		return byProtocol
	case "src_as":
		return bySrcAS
	case "dst_as":
		return byDstAS
	}
	return byNone
}

// qAcc is what a query has gathered from some of the buckets.  A report counts in a map made for the grouping (an address, a pair of
// them or a small number, which hash much faster than a groupKey); a series and the other groupings use groups.
type qAcc struct {
	total, other flowVal
	groups       map[groupKey]flowVal
	addr         map[netip.Addr]flowVal    // host, src, dst, exporter
	pair         map[[2]netip.Addr]flowVal // conversation
	small        map[uint32]flowVal        // service (port<<8|proto), protocol, src_as, dst_as
	tot          map[int64]flowVal         // a series: the total in each slot
	per          map[groupKey]map[int64]flowVal
	hint         int  // keys in the bucket the next maps are made for: they start at a size near what they end up at, not at 8
	approx       bool // something was left out (an hour was cut, or only an hour's biggest groups were kept)
}

func newQAcc(step int64) *qAcc {
	a := &qAcc{groups: map[groupKey]flowVal{}}
	if step > 0 {
		a.tot = map[int64]flowVal{}
		a.per = map[groupKey]map[int64]flowVal{}
	}
	return a
}

func mergeInto[K comparable](dst *map[K]flowVal, src map[K]flowVal) {
	if len(src) == 0 {
		return
	}
	if *dst == nil {
		*dst = make(map[K]flowVal, len(src))
	}
	d := *dst
	for k, v := range src {
		c := d[k]
		c.add(v)
		d[k] = c
	}
}

// merge adds b into a.
func (a *qAcc) merge(b *qAcc) {
	a.total.add(b.total)
	a.other.add(b.other)
	a.approx = a.approx || b.approx
	mergeInto(&a.groups, b.groups)
	mergeInto(&a.addr, b.addr)
	mergeInto(&a.pair, b.pair)
	mergeInto(&a.small, b.small)
	mergeInto(&a.tot, b.tot)
	for g, m := range b.per {
		d := a.per[g]
		if d == nil {
			d = make(map[int64]flowVal, len(m))
			a.per[g] = d
		}
		for t, v := range m {
			c := d[t]
			c.add(v)
			d[t] = c
		}
	}
}

// finish turns the compact maps into groupKey ones, once, for the answer.
func (a *qAcc) finish(by string) {
	add := func(g groupKey, v flowVal) {
		c := a.groups[g]
		c.add(v)
		a.groups[g] = c
	}
	switch byKind(by) {
	case byHost, bySrc, byDst:
		for ad, v := range a.addr {
			add(groupKey{A: ad}, v)
		}
	case byExporter:
		for ad, v := range a.addr {
			add(groupKey{Exp: ad}, v)
		}
	case byConv:
		for p, v := range a.pair {
			add(groupKey{A: p[0], B: p[1]}, v)
		}
	case byService:
		for k, v := range a.small {
			add(groupKey{P1: uint16(k >> 8), Proto: uint8(k)}, v)
		}
	case byProtocol:
		for k, v := range a.small {
			add(groupKey{Proto: uint8(k)}, v)
		}
	case bySrcAS, byDstAS:
		for k, v := range a.small {
			add(groupKey{AS: k}, v)
		}
	}
	a.addr, a.pair, a.small = nil, nil, nil
}

// accBucket adds one bucket to a, as a query q sees it.  lose is q.Losers as a set; step is the series step (0: a report).
func accBucket(a *qAcc, b *flowBucket, q *FlowQuery, lose map[flowLoser]struct{}, step int64) {
	slot := b.TS
	if step > 0 {
		slot = b.TS / step * step
	}
	if b.Trunc > 0 {
		a.approx = true
	}
	kind := byNone
	if step == 0 {
		kind = byKind(q.By)
	}
	var am map[netip.Addr]flowVal
	var pm map[[2]netip.Addr]flowVal
	var sm map[uint32]flowVal
	switch kind {
	case byHost, bySrc, byDst, byExporter:
		if a.addr == nil {
			a.addr = make(map[netip.Addr]flowVal, a.hint/4)
		}
		am = a.addr
	case byConv:
		if a.pair == nil {
			a.pair = make(map[[2]netip.Addr]flowVal, a.hint/2)
		}
		pm = a.pair
	case byService, byProtocol, bySrcAS, byDstAS:
		if a.small == nil {
			a.small = map[uint32]flowVal{}
		}
		sm = a.small
	}
	empty := q.Filter.empty()
	// the sums are kept in locals and added at the end: accumulators of two workers can sit in one cache line, and a field written
	// for every key would bounce it between the cores
	var total, other flowVal
	defer func() {
		a.total.add(total)
		a.other.add(other)
	}()
	if empty {
		total.add(b.Other)
		other.add(b.Other)
	}
	for k, v := range b.M {
		if !empty && !q.Filter.match(k) {
			continue
		}
		if lose != nil && k.Src.IsValid() {
			if _, ok := lose[flowLoser{tupleHash(k), k.Exp}]; ok {
				continue // the same flow, as another exporter saw it: that one counts
			}
		}
		total.add(v)
		if step > 0 {
			c := a.tot[slot]
			c.add(v)
			a.tot[slot] = c
		}
		if q.By == "" {
			continue
		}
		if !k.Src.IsValid() && !k.Dst.IsValid() && kind != byExporter && q.By != "exporter" { // folded: no address to group by
			other.add(v)
			continue
		}
		switch kind {
		case byHost:
			c := am[k.Src]
			c.add(v)
			am[k.Src] = c
			if k.Dst != k.Src {
				c = am[k.Dst]
				c.add(v)
				am[k.Dst] = c
			}
		case bySrc:
			c := am[k.Src]
			c.add(v)
			am[k.Src] = c
		case byDst:
			c := am[k.Dst]
			c.add(v)
			am[k.Dst] = c
		case byExporter:
			c := am[k.Exp]
			c.add(v)
			am[k.Exp] = c
		case byConv:
			x, y := k.Src, k.Dst
			if y.Less(x) {
				x, y = y, x
			}
			c := pm[[2]netip.Addr{x, y}]
			c.add(v)
			pm[[2]netip.Addr{x, y}] = c
		case byService, byProtocol, bySrcAS, byDstAS:
			var key uint32
			switch kind {
			case byService:
				key = uint32(servicePort(k))<<8 | uint32(k.Proto)
			case byProtocol:
				key = uint32(k.Proto)
			case bySrcAS:
				key = k.SrcAS
			default:
				key = k.DstAS
			}
			c := sm[key]
			c.add(v)
			sm[key] = c
		default:
			emit(q.By, k, func(g groupKey) {
				c := a.groups[g]
				c.add(v)
				a.groups[g] = c
				if step > 0 {
					m := a.per[g]
					if m == nil {
						m = map[int64]flowVal{}
						a.per[g] = m
					}
					p := m[slot]
					p.add(v)
					m[slot] = p
				}
			})
		}
	}
}

// ── keeping only an hour's biggest groups ────────────────────────────────────────────────────────────────────────

// truncN is how many groups an hour keeps, by each of bytes and packets, in a report over a long range for a grouping with about
// one group per key.  A host that is among the biggest of a day or more but outside the biggest 1,000 of every hour it appeared
// in has nothing like the traffic of the ones that are in: the answer is marked approximate all the same.
const truncN = 1000

// truncMinHours is how many hourly buckets a report needs before the biggest-groups-only path is used.
const truncMinHours = 24

func highCard(by string) bool {
	switch by {
	case "host", "src", "dst", "conversation", "flow":
		return true
	}
	return false
}

// truncMap drops the groups that are in neither the biggest n by bytes nor the biggest n by packets (nor, when the flow counts are
// not mostly equal, by flows).  It reports whether it dropped any.
func truncMap[K comparable](m map[K]flowVal, n int) bool {
	if len(m) <= n {
		return false
	}
	bs, ps, fs := make([]uint64, 0, len(m)), make([]uint64, 0, len(m)), make([]uint64, 0, len(m))
	for _, v := range m {
		bs, ps, fs = append(bs, v.Bytes), append(ps, v.Packets), append(fs, v.Flows)
	}
	nth := func(x []uint64) uint64 { return nthLargest(x, n) }
	tb, tp, tf := nth(bs), nth(ps), nth(fs)
	nf := 0
	for _, f := range fs {
		if f >= tf {
			nf++
		}
	}
	useF := nf <= 2*n // flows are mostly 1: they say nothing about who is big
	for k, v := range m {
		if v.Bytes >= tb || v.Packets >= tp || (useF && v.Flows >= tf) {
			continue
		}
		delete(m, k)
	}
	return true
}

// nthLargest is the n-th biggest of x (1 = the biggest), found by selection, not by sorting all of x: about 3 passes instead of
// m log m steps.  x is reordered.  The same value as sorting and indexing from the end gives.
func nthLargest(x []uint64, n int) uint64 {
	k := len(x) - n // index of the answer in ascending order
	lo, hi := 0, len(x)-1
	for lo < hi {
		// median of three as the pivot
		mid := lo + (hi-lo)/2
		if x[mid] < x[lo] {
			x[mid], x[lo] = x[lo], x[mid]
		}
		if x[hi] < x[lo] {
			x[hi], x[lo] = x[lo], x[hi]
		}
		if x[hi] < x[mid] {
			x[hi], x[mid] = x[mid], x[hi]
		}
		p := x[mid]
		i, j := lo, hi
		for i <= j {
			for x[i] < p {
				i++
			}
			for x[j] > p {
				j--
			}
			if i <= j {
				x[i], x[j] = x[j], x[i]
				i++
				j--
			}
		}
		switch {
		case k <= j:
			hi = j
		case k >= i:
			lo = i
		default:
			return x[k]
		}
	}
	return x[k]
}

func (a *qAcc) truncate(n int) {
	d := truncMap(a.addr, n)
	d = truncMap(a.pair, n) || d
	d = truncMap(a.groups, n) || d
	if d {
		a.approx = true
	}
}

// ── what an hour holds ───────────────────────────────────────────────────────────────────────────────────────────

// hourIdx is what a report that filters on exporters, ports or protocols needs to know to leave an hour out.
type hourIdx struct {
	exps       []netip.Addr
	ports      []uint16 // both ports of every key, when there are few of them
	portsKnown bool
	protos     [32]byte
}

const idxMaxPorts = 256

func buildIdx(b *flowBucket) *hourIdx {
	ix := &hourIdx{portsKnown: true}
	seenE := map[netip.Addr]struct{}{}
	seenP := map[uint16]struct{}{}
	var lastE netip.Addr
	for k := range b.M {
		if k.Exp != lastE || len(seenE) == 0 {
			if _, ok := seenE[k.Exp]; !ok {
				seenE[k.Exp] = struct{}{}
				ix.exps = append(ix.exps, k.Exp)
			}
			lastE = k.Exp
		}
		ix.protos[k.Proto>>3] |= 1 << (k.Proto & 7)
		if ix.portsKnown {
			seenP[k.SPort] = struct{}{}
			seenP[k.DPort] = struct{}{}
			if len(seenP) > idxMaxPorts {
				ix.portsKnown, seenP = false, nil
			}
		}
	}
	for p := range seenP {
		ix.ports = append(ix.ports, p)
	}
	return ix
}

// cannotMatch: no key of the hour can pass the lists of f that the index covers.
func (ix *hourIdx) cannotMatch(f *FlowFilter) bool {
	if ix == nil {
		return false
	}
	if len(f.Exporters) > 0 {
		found := false
	loop:
		for _, e := range ix.exps {
			for _, p := range f.Exporters {
				if p.Contains(e) {
					found = true
					break loop
				}
			}
		}
		if !found {
			return true
		}
	}
	if len(f.Ports) > 0 && ix.portsKnown {
		found := false
	ploop:
		for _, want := range f.Ports {
			for _, p := range ix.ports {
				if p == want {
					found = true
					break ploop
				}
			}
		}
		if !found {
			return true
		}
	}
	if len(f.Protos) > 0 {
		found := false
		for _, p := range f.Protos {
			if ix.protos[p>>3]&(1<<(p&7)) != 0 {
				found = true
				break
			}
		}
		if !found {
			return true
		}
	}
	return false
}

func (s *flowStore) idxGet(ts int64) *hourIdx {
	s.idxMu.RLock()
	defer s.idxMu.RUnlock()
	return s.idx[ts]
}

func (s *flowStore) idxSet(ts int64, ix *hourIdx) {
	s.idxMu.Lock()
	defer s.idxMu.Unlock()
	if s.idx == nil {
		s.idx = map[int64]*hourIdx{}
	}
	s.idx[ts] = ix
}

// idxPrune forgets the hours that are neither in memory nor on disk any more.
func (s *flowStore) idxPrune(mem map[int64]*flowBucket, disk map[int64]string) {
	s.idxMu.Lock()
	defer s.idxMu.Unlock()
	for ts := range s.idx {
		_, m := mem[ts]
		_, d := disk[ts]
		if !m && !d {
			delete(s.idx, ts)
		}
	}
}

// pruneRefs leaves out the hours the filter cannot match.
func pruneRefs(refs []bucketRef, f *FlowFilter) []bucketRef {
	if f == nil || len(f.Exporters)+len(f.Ports)+len(f.Protos) == 0 {
		return refs
	}
	out := refs[:0:0]
	for _, r := range refs {
		if r.span == 3600 && r.idx.cannotMatch(f) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// ── cold hours ───────────────────────────────────────────────────────────────────────────────────────────────────

// loadHourFile reads an hourly file into a bucket (nil when it cannot be read).
func loadHourFile(path string) *flowBucket {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var b *flowBucket
	readFlowRecs(f, func(r flowFileRec) {
		if b == nil {
			b = &flowBucket{TS: r.TS, M: make(map[flowKey]flowVal, len(r.Entries)), saved: true}
		}
		b.Trunc += r.Trunc
		for _, en := range r.Entries {
			if en.K == (flowKey{}) {
				b.Other.add(en.V)
				continue
			}
			c := b.M[en.K]
			c.add(en.V)
			b.M[en.K] = c
		}
	})
	return b
}

// bucketOf is the bucket of a ref: the one in memory, or the one read from the hour's file (and its index remembered).
func (s *flowStore) bucketOf(r bucketRef) *flowBucket {
	if r.b != nil {
		return r.b
	}
	b := loadHourFile(r.cold)
	if b != nil && r.idx == nil {
		s.idxSet(r.ts, buildIdx(b))
	}
	return b
}

// refSig tells the cache which version of an hour it saw: the bucket's size, or the file's.
func refSig(r bucketRef) uint64 {
	if r.b != nil {
		h := fnv.New64a()
		var x [48]byte
		put := func(i int, v uint64) {
			for j := 0; j < 8; j++ {
				x[i*8+j] = byte(v >> (8 * j))
			}
		}
		put(0, uint64(len(r.b.M)))
		put(1, uint64(r.b.Trunc))
		put(2, r.b.Other.Bytes)
		put(3, r.b.Other.Packets)
		put(4, r.b.Other.Flows)
		h.Write(x[:])
		return h.Sum64()
	}
	if fi, err := os.Stat(r.cold); err == nil {
		return uint64(fi.Size())*1000003 ^ uint64(fi.ModTime().UnixNano()) | 1<<63
	}
	return 0
}

// ── running a query ──────────────────────────────────────────────────────────────────────────────────────────────

// workersFor is how many goroutines to give a job over refs.
func workersFor(refs []bucketRef) int {
	n := runtime.GOMAXPROCS(0)
	if n > len(refs) {
		n = len(refs)
	}
	if n < 2 {
		return 1
	}
	keys := 0
	for _, r := range refs {
		if r.b == nil {
			keys += 20000 // a cold hour: read it in parallel too
		} else {
			keys += len(r.b.M)
		}
	}
	if keys < parallelMinKeys {
		return 1
	}
	return n
}

// runWorkers calls fn(worker, i) for every i < n, on up to w goroutines.
func runWorkers(n, w int, fn func(worker, i int)) {
	if w <= 1 {
		for i := 0; i < n; i++ {
			fn(0, i)
		}
		return
	}
	var next atomic.Int64
	var wg sync.WaitGroup
	for wi := 0; wi < w; wi++ {
		wg.Add(1)
		go func(wi int) {
			defer wg.Done()
			for {
				i := int(next.Add(1)) - 1
				if i >= n {
					return
				}
				fn(wi, i)
			}
		}(wi)
	}
	wg.Wait()
}

// accumulate gathers a query over refs, in parallel when it is big, and from the cache for the hours it has.
func (s *flowStore) accumulate(q *FlowQuery, lose map[flowLoser]struct{}, step int64, refs []bucketRef) *qAcc {
	var hitAccs []*qAcc
	var ck *qcacheKey
	useTrunc := false
	if step == 0 && qcache != nil {
		if highCard(q.By) {
			nh := 0
			for _, r := range refs {
				if r.span == 3600 {
					nh++
				}
			}
			useTrunc = nh >= truncMinHours
		}
		if cacheableBy(q.By) || useTrunc {
			ck = qcache.keyFor(q, useTrunc)
		}
	}
	type sigRef struct {
		bucketRef
		sig uint64
	}
	todo := make([]sigRef, 0, len(refs))
	for _, r := range refs {
		var sig uint64
		if ck != nil && r.span == 3600 {
			sig = refSig(r)
			if p := qcache.get(ck, r.ts, sig); p != nil {
				hitAccs = append(hitAccs, p)
				continue
			}
		}
		todo = append(todo, sigRef{r, sig})
	}
	w := 1
	{
		rs := make([]bucketRef, len(todo))
		for i, t := range todo {
			rs[i] = t.bucketRef
		}
		w = workersFor(rs)
	}
	// each worker makes its own accumulator, on its own goroutine: the maps' headers are written for every key, and two made one
	// after the other can share a cache line, which the cores then fight over
	accs := make([]*qAcc, w)
	runWorkers(len(todo), w, func(wi, i int) {
		if accs[wi] == nil {
			accs[wi] = newQAcc(step)
		}
		t := todo[i]
		b := s.bucketOf(t.bucketRef)
		if b == nil {
			return
		}
		if ck != nil && t.span == 3600 {
			p := newQAcc(0)
			p.hint = len(b.M)
			accBucket(p, b, q, lose, 0)
			if useTrunc {
				p.truncate(truncN)
			}
			qcache.put(ck, t.ts, t.sig, len(b.M), p)
			accs[wi].merge(p)
			return
		}
		accBucket(accs[wi], b, q, lose, step)
	})
	var out *qAcc // the biggest accumulators are not copied: the rest is added into the first
	for _, a := range accs {
		switch {
		case a == nil:
		case out == nil:
			out = a
		default:
			out.merge(a)
		}
	}
	if out == nil {
		out = newQAcc(step)
	}
	for _, p := range hitAccs {
		out.merge(p)
	}
	return out
}

// ── the cache ────────────────────────────────────────────────────────────────────────────────────────────────────

// cacheableBy: a grouping with few groups per hour.
func cacheableBy(by string) bool {
	switch by {
	case "", "service", "protocol", "exporter", "interface", "src_as", "dst_as":
		return true
	}
	return false
}

// qcacheBudget is what the cache keeps, in group entries (about 150 bytes each in memory), by the machine's memory: 1/50 of it,
// between 200,000 (30 MB) and 2,000,000 (300 MB).
func qcacheBudget() int {
	n := int(machineMemory() / 50 / 150)
	if n < 200000 {
		n = 200000
	}
	if n > 2000000 {
		n = 2000000
	}
	return n
}

type qcacheKey struct {
	filter uint64 // hash of the filter, as the node sees it after wildcards are expanded
	by     string
	losers uint64
	trunc  bool
}

type qcacheEnt struct {
	acc     *qAcc
	sig     uint64 // the version of the hour this was made from
	used    int64
	nGroups int
}

type qcacheSlot struct {
	k  qcacheKey
	ts int64
}

type queryCache struct {
	mu     sync.Mutex
	m      map[qcacheSlot]*qcacheEnt
	groups int
	budget int
	tick   int64
	hits   atomic.Int64
	misses atomic.Int64
}

var qcache = &queryCache{m: map[qcacheSlot]*qcacheEnt{}, budget: qcacheBudget()}

// keyFor is the part of a query that decides what a bucket contributes to it.
func (c *queryCache) keyFor(q *FlowQuery, trunc bool) *qcacheKey {
	fb, err := json.Marshal(&q.Filter)
	if err != nil {
		return nil
	}
	h := fnv.New64a()
	h.Write(fb)
	var lh uint64
	for _, l := range q.Losers { // in any order
		x := l.H ^ uint64(len(l.Exp.AsSlice()))*0x9e3779b97f4a7c15
		for _, b := range l.Exp.AsSlice() {
			x = (x ^ uint64(b)) * 1099511628211
		}
		x ^= x >> 29
		x *= 0xbf58476d1ce4e5b9
		x ^= x >> 32
		lh += x
	}
	return &qcacheKey{filter: h.Sum64(), by: q.By, losers: lh + uint64(len(q.Losers)), trunc: trunc}
}

func (c *queryCache) get(k *qcacheKey, ts int64, sig uint64) *qAcc {
	c.mu.Lock()
	defer c.mu.Unlock()
	e := c.m[qcacheSlot{*k, ts}]
	if e == nil || e.sig != sig {
		c.misses.Add(1)
		return nil
	}
	c.tick++
	e.used = c.tick
	c.hits.Add(1)
	return e.acc
}

func accGroups(a *qAcc) int { return len(a.groups) + len(a.addr) + len(a.pair) + len(a.small) }

// put keeps a (read-only from now on) for the hour ts.  nKeys is the size of the hour: a result about as big as the hour itself is
// not worth the memory.
func (c *queryCache) put(k *qcacheKey, ts int64, sig uint64, nKeys int, a *qAcc) {
	n := accGroups(a)
	if n > c.budget/20 || n*2 > nKeys && n > 100 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	slot := qcacheSlot{*k, ts}
	if old := c.m[slot]; old != nil {
		c.groups -= old.nGroups
	}
	c.tick++
	c.m[slot] = &qcacheEnt{acc: a, sig: sig, used: c.tick, nGroups: n + 1}
	c.groups += n + 1
	for c.groups > c.budget {
		var oldest qcacheSlot
		var ot int64 = 1 << 62
		for s, e := range c.m {
			if e.used < ot {
				oldest, ot = s, e.used
			}
		}
		c.groups -= c.m[oldest].nGroups
		delete(c.m, oldest)
	}
}

// prewarm puts what the common groupings take from a new hour in the cache, as the hour is made: a report over the days before
// finds them there.  (A report with deduplication losers has other keys and computes its own.)
func prewarm(b *flowBucket) {
	if qcache == nil {
		return
	}
	sig := refSig(bucketRef{b: b})
	for _, by := range []string{"", "service", "protocol", "exporter", "src_as", "dst_as"} {
		q := &FlowQuery{By: by}
		ck := qcache.keyFor(q, false)
		if ck == nil {
			continue
		}
		p := newQAcc(0)
		accBucket(p, b, q, nil, 0)
		qcache.put(ck, b.TS, sig, len(b.M), p)
	}
}

// ── timeouts ─────────────────────────────────────────────────────────────────────────────────────────────────────

// flowRoundTimeout is how long a node gets to answer one round of a query over [from, to): a short range is quick, a long one
// walks a great many keys.
func flowRoundTimeout(from, to int64) time.Duration {
	span := to - from
	switch {
	case span <= 6*3600:
		return 10 * time.Second
	case span <= 7*86400:
		return 30 * time.Second
	}
	return 100 * time.Second
}

// flowReportTimeout is how long the asking side waits for a whole report (two rounds).
func flowReportTimeout(q FlowQuery) time.Duration {
	d := 2*flowRoundTimeout(q.From, q.To) + 10*time.Second
	if d < 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

// ── exporters of a range ─────────────────────────────────────────────────────────────────────────────────────────

// flowExps is the exporters a node has for a range, up to two (two are enough to know a report needs deduplicating).
type flowExps struct {
	Addrs   []netip.Addr `json:"addrs,omitempty"`
	Unknown bool         `json:"unknown,omitempty"`
}

func (s *flowStore) rangeExporters(q FlowQuery) flowExps {
	s.mu.RLock()
	defer s.mu.RUnlock()
	refs, _, _ := s.bucketsLocked(q.From, q.To)
	seen := map[netip.Addr]struct{}{}
	var out flowExps
	add := func(a netip.Addr) bool {
		if _, ok := seen[a]; !ok {
			seen[a] = struct{}{}
			out.Addrs = append(out.Addrs, a)
		}
		return len(seen) >= 2
	}
	for _, r := range refs {
		if r.idx != nil {
			for _, e := range r.idx.exps {
				if add(e) {
					return out
				}
			}
			continue
		}
		if r.b == nil { // an hour only on disk, not looked at yet
			return flowExps{Unknown: true}
		}
		for k := range r.b.M {
			if add(k.Exp) {
				return out
			}
		}
	}
	return out
}
