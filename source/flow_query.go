package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Queries over the rollups of one node (the cluster-wide answer is the sum of the nodes' answers: flow_cluster.go).

// FlowFilter narrows a report.  Every field that is set must match; a list matches when any of its entries does.
type FlowFilter struct {
	Exporters []netip.Prefix `json:"exporters,omitempty"`
	Hosts     []netip.Prefix `json:"hosts,omitempty"` // the source or the destination
	Src       []netip.Prefix `json:"src,omitempty"`
	Dst       []netip.Prefix `json:"dst,omitempty"`
	// wildcard patterns (flow_glob.go): every node turns them into addresses of its own before it scans
	HostGlobs []string `json:"host_globs,omitempty"`
	SrcGlobs  []string `json:"src_globs,omitempty"`
	DstGlobs  []string `json:"dst_globs,omitempty"`
	Ports     []uint16 `json:"ports,omitempty"` // the service port (either side)
	Protos    []uint8  `json:"protos,omitempty"`
	Ifs       []uint32 `json:"ifs,omitempty"` // an interface index, in or out
	AS        []uint32 `json:"as,omitempty"`  // either side
	// Expr is a filter with AND, OR and NOT (flow_api.go parses it); the flows must match it as well as the lists above.
	Expr *FlowExpr `json:"expr,omitempty"`
}

// FlowExpr is a tree of terms joined by and, or and not.  A term is a FlowFilter with one list set (host=10.0.0.5, port=443,53):
// within a term the values are alternatives, as in the lists above.
type FlowExpr struct {
	Op   string      `json:"op"` // and, or, not or term
	Kids []*FlowExpr `json:"kids,omitempty"`
	Term *FlowFilter `json:"term,omitempty"`
}

func (e *FlowExpr) eval(k flowKey) bool {
	switch e.Op {
	case "and":
		for _, c := range e.Kids {
			if !c.eval(k) {
				return false
			}
		}
		return true
	case "or":
		for _, c := range e.Kids {
			if c.eval(k) {
				return true
			}
		}
		return false
	case "not":
		return len(e.Kids) == 1 && !e.Kids[0].eval(k)
	case "term":
		return e.Term != nil && e.Term.match(k)
	}
	return false
}

const maxExprNodes, maxExprDepth = 200, 24

// check bounds a tree that came from a peer or a caller: shape, size and depth.
func (e *FlowExpr) check(depth int, nodes *int) error {
	*nodes++
	if e == nil || depth > maxExprDepth || *nodes > maxExprNodes {
		return fmt.Errorf("filter: too big")
	}
	switch e.Op {
	case "and", "or":
		if len(e.Kids) < 1 {
			return fmt.Errorf("filter: %s of nothing", e.Op)
		}
	case "not":
		if len(e.Kids) != 1 {
			return fmt.Errorf("filter: not takes one term")
		}
	case "term":
		if e.Term == nil || e.Term.Expr != nil || e.Term.empty() {
			return fmt.Errorf("filter: an empty term")
		}
	default:
		return fmt.Errorf("filter: unknown operator %q", e.Op)
	}
	for _, c := range e.Kids {
		if err := c.check(depth+1, nodes); err != nil {
			return err
		}
	}
	return nil
}

func (f *FlowFilter) empty() bool {
	return f == nil || len(f.Exporters)+len(f.Hosts)+len(f.Src)+len(f.Dst)+len(f.HostGlobs)+len(f.SrcGlobs)+len(f.DstGlobs)+len(f.Ports)+len(f.Protos)+len(f.Ifs)+len(f.AS) == 0 && f.Expr == nil
}

func inPrefixes(ps []netip.Prefix, a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (f *FlowFilter) match(k flowKey) bool {
	if f.Expr != nil {
		if !k.Src.IsValid() && !k.Dst.IsValid() {
			return false // the "other" entry has no addresses to test: a NOT would let everything of it through
		}
		if !f.Expr.eval(k) {
			return false
		}
	}
	if len(f.Exporters) > 0 {
		ok := false
		for _, e := range f.Exporters {
			if e.Contains(k.Exp) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.Hosts)+len(f.Src)+len(f.Dst)+len(f.Ports)+len(f.Protos)+len(f.AS)+len(f.Ifs) > 0 && !k.Src.IsValid() && !k.Dst.IsValid() {
		return false // the "other" entry has nothing to compare
	}
	if len(f.Hosts) > 0 && !inPrefixes(f.Hosts, k.Src) && !inPrefixes(f.Hosts, k.Dst) {
		return false
	}
	if len(f.Src) > 0 && !inPrefixes(f.Src, k.Src) {
		return false
	}
	if len(f.Dst) > 0 && !inPrefixes(f.Dst, k.Dst) {
		return false
	}
	if len(f.Ports) > 0 {
		ok := false
		for _, p := range f.Ports {
			if p == k.SPort || p == k.DPort {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.Protos) > 0 {
		ok := false
		for _, p := range f.Protos {
			if p == k.Proto {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.Ifs) > 0 {
		ok := false
		for _, i := range f.Ifs {
			if i == k.InIf || i == k.OutIf {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(f.AS) > 0 {
		ok := false
		for _, a := range f.AS {
			if a == k.SrcAS || a == k.DstAS {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// oldest is the time of the oldest bucket this node holds (0 when it holds none).
func (s *flowStore) oldest() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var o int64
	for t := range s.hour {
		if o == 0 || t < o {
			o = t
		}
	}
	for t := range s.min {
		if o == 0 || t < o {
			o = t
		}
	}
	for t := range s.diskHours { // hours that are only on disk are reported too
		if o == 0 || t < o {
			o = t
		}
	}
	return o
}

// FlowQuery is a report request.
type FlowQuery struct {
	From   int64  `json:"from"` // unix seconds, inclusive
	To     int64  `json:"to"`   // exclusive
	By     string `json:"by"`
	Metric string `json:"metric,omitempty"` // bytes (default), packets or flows
	Limit  int    `json:"limit,omitempty"`
	Step   int    `json:"step,omitempty"` // seconds; > 0 asks for a time series
	// NoDedupe adds up every exporter's report of a flow.  By default a flow that several exporters report (a path of switches, a
	// switch and a firewall) is counted once, as the exporter that saw most of it reports it (see the deduplication section below).
	NoDedupe bool `json:"no_dedupe,omitempty"`
	// Losers is what the asking node sends the others in the second round of a deduplicated report: the (flow, exporter) pairs to
	// leave out.  A node that is sent none counts everything.
	Losers []flowLoser `json:"losers,omitempty"`
	Filter FlowFilter  `json:"filter"`
}

// FlowRow is one line of a report.
type FlowRow struct {
	Key     map[string]string `json:"group"`
	Bytes   uint64            `json:"bytes"`
	Packets uint64            `json:"packets"`
	Flows   uint64            `json:"flows"`
	// Set when the answer is built for a person (flow_api.go), not by the nodes:
	Names map[string]string `json:"names,omitempty"` // exporter, DNS and service names for the key
	Share float64           `json:"share_pct,omitempty"`
	Bps   float64           `json:"avg_bits_per_sec,omitempty"`
}

type FlowPoint struct {
	T       int64  `json:"t"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

// FlowSeries is a time series: for one group, or (Key nil) for everything that matched.
type FlowSeries struct {
	Key    map[string]string `json:"group,omitempty"`
	Points []FlowPoint       `json:"points"`
}

// FlowAnswer is one node's answer, or the merged answer of the cluster.
type FlowAnswer struct {
	Rows      []FlowRow    `json:"rows,omitempty"`
	Total     FlowRow      `json:"total"`
	Other     FlowRow      `json:"other,omitempty"` // in the total but in no row: keys a limit folded together (see flow_store.go)
	Series    []FlowSeries `json:"series,omitempty"`
	Approx    bool         `json:"approximate,omitempty"`  // an hourly bucket that dropped small keys was used
	Cut       bool         `json:"cut,omitempty"`          // a node cut its list: lower rows can be low
	Resolved  string       `json:"resolution,omitempty"`   // minute, hour or mixed
	Deduped   bool         `json:"deduplicated,omitempty"` // a flow several exporters reported was counted once
	DedupeCut bool         `json:"dedupe_cut,omitempty"`   // a node's digest was cut: its smallest flows were not weighed
}

type groupKey struct {
	Exp, A, B netip.Addr
	P1, P2    uint16
	Proto     uint8
	If        uint32
	Dir       uint8
	AS        uint32
}

var flowGroupings = []string{"src", "dst", "host", "conversation", "flow", "service", "protocol", "exporter", "interface", "src_as", "dst_as"}

func validFlowBy(by string) bool {
	for _, g := range flowGroupings {
		if g == by {
			return true
		}
	}
	return false
}

// servicePort is the port that names the service: the one that is set, or the smaller when both are.
func servicePort(k flowKey) uint16 {
	switch {
	case k.SPort == 0:
		return k.DPort
	case k.DPort == 0:
		return k.SPort
	case k.SPort < k.DPort:
		return k.SPort
	}
	return k.DPort
}

// emit calls f with each group a key belongs to.
func emit(by string, k flowKey, f func(groupKey)) {
	switch by {
	case "src":
		f(groupKey{A: k.Src})
	case "dst":
		f(groupKey{A: k.Dst})
	case "host":
		f(groupKey{A: k.Src})
		if k.Dst != k.Src {
			f(groupKey{A: k.Dst})
		}
	case "conversation":
		a, b := k.Src, k.Dst
		if b.Less(a) {
			a, b = b, a
		}
		f(groupKey{A: a, B: b})
	case "flow":
		f(groupKey{A: k.Src, B: k.Dst, P1: servicePort(k), Proto: k.Proto})
	case "service":
		f(groupKey{P1: servicePort(k), Proto: k.Proto})
	case "protocol":
		f(groupKey{Proto: k.Proto})
	case "exporter":
		f(groupKey{Exp: k.Exp})
	case "interface":
		if k.InIf != 0 {
			f(groupKey{Exp: k.Exp, If: k.InIf, Dir: 1})
		}
		if k.OutIf != 0 {
			f(groupKey{Exp: k.Exp, If: k.OutIf, Dir: 2})
		}
	case "src_as":
		f(groupKey{AS: k.SrcAS})
	case "dst_as":
		f(groupKey{AS: k.DstAS})
	}
}

func addrStr(a netip.Addr) string {
	if !a.IsValid() {
		return "other"
	}
	return a.String()
}

// dims names a group's fields, for the answer.
func (g groupKey) dims(by string) map[string]string {
	switch by {
	case "src":
		return map[string]string{"src": addrStr(g.A)}
	case "dst":
		return map[string]string{"dst": addrStr(g.A)}
	case "host":
		return map[string]string{"host": addrStr(g.A)}
	case "conversation":
		return map[string]string{"a": addrStr(g.A), "b": addrStr(g.B)}
	case "flow":
		return map[string]string{"src": addrStr(g.A), "dst": addrStr(g.B), "proto": strconv.Itoa(int(g.Proto)), "port": strconv.Itoa(int(g.P1))}
	case "service":
		return map[string]string{"proto": strconv.Itoa(int(g.Proto)), "port": strconv.Itoa(int(g.P1))}
	case "protocol":
		return map[string]string{"proto": strconv.Itoa(int(g.Proto))}
	case "exporter":
		return map[string]string{"exporter": addrStr(g.Exp)}
	case "interface":
		d := "in"
		if g.Dir == 2 {
			d = "out"
		}
		return map[string]string{"exporter": addrStr(g.Exp), "ifindex": strconv.FormatUint(uint64(g.If), 10), "direction": d}
	case "src_as", "dst_as":
		return map[string]string{"as": strconv.FormatUint(uint64(g.AS), 10)}
	}
	return nil
}

// rowKey is the string two nodes' rows are matched by.
func rowKey(m map[string]string) string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(m[k])
		b.WriteByte('|')
	}
	return b.String()
}

func metricOf(v flowVal, metric string) uint64 {
	switch metric {
	case "packets":
		return v.Packets
	case "flows":
		return v.Flows
	}
	return v.Bytes
}

func validMetric(m string) bool { return m == "" || m == "bytes" || m == "packets" || m == "flows" }

// slice is a bucket, with the time it covers.
type bucketRef struct {
	b    *flowBucket // nil for a cold hour: one that is only on disk
	span int64
	ts   int64
	cold string   // the file of a cold hour
	idx  *hourIdx // what an hour holds (nil: not known)
}

// buckets lists what covers [from, to): hourly buckets for hours that lie wholly inside, minute buckets for the rest.
func (s *flowStore) bucketsLocked(from, to int64) (out []bucketRef, approx bool, res string) {
	from = from / 60 * 60
	to = (to + 59) / 60 * 60
	nh, nm := 0, 0
	for h := from / 3600 * 3600; h < to; h += 3600 {
		whole := h >= from && h+3600 <= to
		if hb := s.hour[h]; hb != nil && whole {
			out = append(out, bucketRef{b: hb, span: 3600, ts: h, idx: s.idxGet(h)})
			if hb.Trunc > 0 {
				approx = true
			}
			nh++
			continue
		}
		if whole && s.hour[h] == nil {
			if path, ok := s.diskHours[h]; ok { // an hour the memory cap left on disk (its file has all of it): read when asked for
				out = append(out, bucketRef{span: 3600, ts: h, cold: path, idx: s.idxGet(h)})
				nh++
				continue
			}
		}
		lo, hi := h, h+3600
		if lo < from {
			lo = from
		}
		if hi > to {
			hi = to
		}
		for t := lo; t < hi; t += 60 {
			if b := s.min[t]; b != nil {
				out = append(out, bucketRef{b: b, span: 60, ts: t})
				nm++
			}
		}
	}
	switch {
	case nh > 0 && nm > 0:
		res = "mixed"
	case nh > 0:
		res = "hour"
	default:
		res = "minute"
	}
	return
}

// Query answers a report (q.Step == 0) or a time series (q.Step > 0) from this node's rollups.
func (s *flowStore) Query(q FlowQuery) FlowAnswer {
	q = s.expandGlobs(q)
	limit := orDef(q.Limit, 20)
	if limit > 1000 {
		limit = 1000
	}
	keep := limit * 5 // a node sends more than the asker wants: the cluster adds the nodes' lists up
	if keep < 1000 {
		keep = 1000
	}
	s.mu.RLock()
	refs, approx, res := s.bucketsLocked(q.From, q.To)
	refs = pruneRefs(refs, &q.Filter)
	ans := FlowAnswer{Approx: approx, Resolved: res}
	var lose map[flowLoser]struct{}
	if len(q.Losers) > 0 {
		lose = make(map[flowLoser]struct{}, len(q.Losers))
		for _, l := range q.Losers {
			lose[l] = struct{}{}
		}
	}
	step := int64(q.Step)
	if step > 0 && step < 60 {
		step = 60
	}
	// what is in memory is read under the lock; the hours that are only on disk after it (the collector is not held up by the disk)
	mem, cold := splitCold(refs)
	acc := s.accumulate(&q, lose, step, mem)
	s.mu.RUnlock()
	if len(cold) > 0 {
		acc.merge(s.accumulate(&q, lose, step, cold))
	}
	acc.finish(q.By)
	ans.Approx = ans.Approx || acc.approx
	groups, total, other, tot, per := acc.groups, acc.total, acc.other, acc.tot, acc.per
	ans.Total = FlowRow{Bytes: total.Bytes, Packets: total.Packets, Flows: total.Flows}
	if q.By != "exporter" {
		ans.Other = FlowRow{Bytes: other.Bytes, Packets: other.Packets, Flows: other.Flows}
	}
	if q.By != "" {
		type gv struct {
			g groupKey
			v flowVal
		}
		all := make([]gv, 0, len(groups))
		for g, v := range groups {
			all = append(all, gv{g, v})
		}
		sort.Slice(all, func(i, j int) bool {
			a, b := metricOf(all[i].v, q.Metric), metricOf(all[j].v, q.Metric)
			if a != b {
				return a > b
			}
			return all[i].g.A.Less(all[j].g.A)
		})
		if len(all) > keep {
			all, ans.Cut = all[:keep], true
		}
		for _, e := range all {
			ans.Rows = append(ans.Rows, FlowRow{Key: e.g.dims(q.By), Bytes: e.v.Bytes, Packets: e.v.Packets, Flows: e.v.Flows})
		}
		if step > 0 {
			n := limit * 3
			for i, e := range all {
				if i >= n {
					break
				}
				ans.Series = append(ans.Series, FlowSeries{Key: e.g.dims(q.By), Points: pointsOf(per[e.g])})
			}
		}
	}
	if step > 0 {
		ans.Series = append([]FlowSeries{{Points: pointsOf(tot)}}, ans.Series...)
	}
	return ans
}

// ── deduplication ───────────────────────────────────────────────────────────────────────────────────────────────
//
// A flow several exporters report (a path of switches, a switch and a firewall) is counted once.  What makes two exporters' keys
// the same flow is the two addresses, the service port and the protocol: not the exporter, its interfaces or the AS numbers.  For
// each such flow, over the range of the query, the exporter that counted the most bytes (then packets, then the lower address) is
// the one that counts.  Exporters on different nodes (anycast) are weighed against each other in two rounds: every node sends a
// digest (flow hash, exporter, bytes, packets), the asking node picks the losers, and sends them back with the query itself.

type flowLoser struct {
	H   uint64     `json:"h"`
	Exp netip.Addr `json:"e"`
}

// digestEnt is what one exporter counted of one flow in a range.
type digestEnt struct {
	H    uint64     `json:"h"`
	Exp  netip.Addr `json:"e"`
	B, P uint64
}

// FlowDigest is a node's side of the first round.  Cut: the node sent only its biggest flows.
type FlowDigest struct {
	Ents []digestEnt `json:"ents,omitempty"`
	Cut  bool        `json:"cut,omitempty"`
}

const maxDigestEnts = 100000

// tupleHash is a 64-bit FNV-1a of a key's flow.  It is the same on every node and every build.
func tupleHash(k flowKey) uint64 {
	h := uint64(14695981039346656037)
	add := func(b []byte) {
		for _, c := range b {
			h ^= uint64(c)
			h *= 1099511628211
		}
	}
	s, d := k.Src.As16(), k.Dst.As16()
	add(s[:])
	add(d[:])
	add([]byte{byte(k.SPort >> 8), byte(k.SPort), byte(k.DPort >> 8), byte(k.DPort), k.Proto})
	return h
}

func dedupes(q FlowQuery) bool { return !q.NoDedupe && q.By != "exporter" && q.By != "interface" }

type dk struct {
	h uint64
	e netip.Addr
}

// splitCold separates the refs in memory from the hours that are only on disk.
func splitCold(refs []bucketRef) (mem, cold []bucketRef) {
	for _, r := range refs {
		if r.b == nil {
			cold = append(cold, r)
		} else {
			mem = append(mem, r)
		}
	}
	return
}

// Digest lists what each exporter counted of each flow the query's filter lets through, the biggest maxDigestEnts of them.
func (s *flowStore) Digest(q FlowQuery) FlowDigest {
	q = s.expandGlobs(q)
	s.mu.RLock()
	refs, _, _ := s.bucketsLocked(q.From, q.To)
	refs = pruneRefs(refs, &q.Filter)
	mem, cold := splitCold(refs)
	ms := s.digestRefs(q, mem)
	s.mu.RUnlock()
	ms = append(ms, s.digestRefs(q, cold)...)
	return digestOut(ms)
}

// digestRefs adds up what each exporter counted of each flow in refs, one map per worker.
func (s *flowStore) digestRefs(q FlowQuery, refs []bucketRef) []map[dk]*digestEnt {
	empty := q.Filter.empty()
	w := workersFor(refs)
	ms := make([]map[dk]*digestEnt, w)
	runWorkers(len(refs), w, func(wi, i int) {
		if ms[wi] == nil { // made here, on the worker's own goroutine (flow_qpar.go says why)
			ms[wi] = map[dk]*digestEnt{}
		}
		m := ms[wi]
		b := s.bucketOf(refs[i])
		if b == nil {
			return
		}
		for k, v := range b.M {
			if !k.Src.IsValid() || (!empty && !q.Filter.match(k)) {
				continue
			}
			h := tupleHash(k)
			e := m[dk{h, k.Exp}]
			if e == nil {
				e = &digestEnt{H: h, Exp: k.Exp}
				m[dk{h, k.Exp}] = e
			}
			e.B += v.Bytes
			e.P += v.Packets
		}
	})
	return ms
}

func digestOut(ms []map[dk]*digestEnt) FlowDigest {
	var m map[dk]*digestEnt
	for _, o := range ms {
		if m == nil {
			m = o
			continue
		}
		for k, e := range o {
			if d := m[k]; d != nil {
				d.B += e.B
				d.P += e.P
			} else {
				m[k] = e
			}
		}
	}
	if m == nil {
		m = map[dk]*digestEnt{}
	}
	out := FlowDigest{Ents: make([]digestEnt, 0, len(m))}
	for _, e := range m {
		out.Ents = append(out.Ents, *e)
	}
	if len(out.Ents) > maxDigestEnts {
		sort.Slice(out.Ents, func(i, j int) bool { return out.Ents[i].B > out.Ents[j].B })
		out.Ents, out.Cut = out.Ents[:maxDigestEnts], true
	}
	return out
}

// chooseLosers takes the nodes' digests and names, for each flow more than one exporter reported, the exporters whose reports are
// left out.
func chooseLosers(ds []FlowDigest) []flowLoser {
	per := map[uint64][]digestEnt{}
	for _, d := range ds {
		for _, e := range d.Ents {
			l := per[e.H]
			found := false
			for i := range l {
				if l[i].Exp == e.Exp { // the same exporter on two nodes (its packets moved): one exporter
					l[i].B += e.B
					l[i].P += e.P
					found = true
					break
				}
			}
			if !found {
				l = append(l, e)
			}
			per[e.H] = l
		}
	}
	var out []flowLoser
	for h, l := range per {
		if len(l) < 2 {
			continue
		}
		best := 0
		for i := 1; i < len(l); i++ {
			a, b := l[i], l[best]
			if a.B > b.B || a.B == b.B && (a.P > b.P || a.P == b.P && a.Exp.Less(b.Exp)) {
				best = i
			}
		}
		for i, e := range l {
			if i != best {
				out = append(out, flowLoser{h, e.Exp})
			}
		}
	}
	return out
}

func pointsOf(m map[int64]flowVal) []FlowPoint {
	out := make([]FlowPoint, 0, len(m))
	for t, v := range m {
		out = append(out, FlowPoint{t, v.Bytes, v.Packets, v.Flows})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}

// mergeFlowAnswers adds nodes' answers up and cuts the list to limit.
func mergeFlowAnswers(parts []FlowAnswer, q FlowQuery) FlowAnswer {
	limit := orDef(q.Limit, 20)
	if limit > 1000 {
		limit = 1000
	}
	var out FlowAnswer
	rows := map[string]*FlowRow{}
	series := map[string]*FlowSeries{}
	pts := map[string]map[int64]FlowPoint{}
	res := ""
	for _, p := range parts {
		out.Total.Bytes += p.Total.Bytes
		out.Total.Packets += p.Total.Packets
		out.Total.Flows += p.Total.Flows
		out.Other.Bytes += p.Other.Bytes
		out.Other.Packets += p.Other.Packets
		out.Other.Flows += p.Other.Flows
		out.Approx = out.Approx || p.Approx
		out.Cut = out.Cut || p.Cut
		if res == "" {
			res = p.Resolved
		} else if res != p.Resolved && p.Resolved != "" {
			res = "mixed"
		}
		for _, r := range p.Rows {
			k := rowKey(r.Key)
			if c := rows[k]; c != nil {
				c.Bytes += r.Bytes
				c.Packets += r.Packets
				c.Flows += r.Flows
			} else {
				rc := r
				rows[k] = &rc
			}
		}
		for _, s := range p.Series {
			k := rowKey(s.Key)
			if series[k] == nil {
				series[k] = &FlowSeries{Key: s.Key}
				pts[k] = map[int64]FlowPoint{}
			}
			for _, pt := range s.Points {
				c := pts[k][pt.T]
				c.T = pt.T
				c.Bytes += pt.Bytes
				c.Packets += pt.Packets
				c.Flows += pt.Flows
				pts[k][pt.T] = c
			}
		}
	}
	out.Resolved = res
	all := make([]FlowRow, 0, len(rows))
	for _, r := range rows {
		all = append(all, *r)
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := metricOfRow(all[i], q.Metric), metricOfRow(all[j], q.Metric)
		if a != b {
			return a > b
		}
		return rowKey(all[i].Key) < rowKey(all[j].Key)
	})
	if len(all) > limit {
		all = all[:limit]
	}
	out.Rows = all
	if q.Step > 0 {
		want := map[string]bool{"": true}
		for _, r := range all {
			want[rowKey(r.Key)] = true
		}
		for k, s := range series {
			if !want[k] {
				continue
			}
			for _, pt := range pts[k] {
				s.Points = append(s.Points, pt)
			}
			if s.Points == nil {
				s.Points = []FlowPoint{} // [] and not null: a client loops over it
			}
			sort.Slice(s.Points, func(i, j int) bool { return s.Points[i].T < s.Points[j].T })
			out.Series = append(out.Series, *s)
		}
		sort.Slice(out.Series, func(i, j int) bool {
			if (out.Series[i].Key == nil) != (out.Series[j].Key == nil) {
				return out.Series[i].Key == nil
			}
			return rowKey(out.Series[i].Key) < rowKey(out.Series[j].Key)
		})
	}
	return out
}

func metricOfRow(r FlowRow, metric string) uint64 {
	return metricOf(flowVal{r.Bytes, r.Packets, r.Flows}, metric)
}

// Validate checks a query that came from the API or a peer.
func (q *FlowQuery) Validate() error {
	if q.By != "" && !validFlowBy(q.By) {
		return fmt.Errorf("by: one of %s", strings.Join(flowGroupings, ", "))
	}
	if q.Filter.Expr != nil {
		n := 0
		if err := q.Filter.Expr.check(0, &n); err != nil {
			return err
		}
	}
	if !validMetric(q.Metric) {
		return fmt.Errorf("metric: bytes, packets or flows")
	}
	if q.To <= q.From {
		return fmt.Errorf("the range is empty")
	}
	if q.To-q.From > 3660*86400 {
		return fmt.Errorf("the range is longer than 10 years")
	}
	if q.Step < 0 || (q.Step > 0 && (q.To-q.From)/int64(maxInt(q.Step, 60)) > 5000) {
		return fmt.Errorf("step: too small for the range (at most 5000 points)")
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
