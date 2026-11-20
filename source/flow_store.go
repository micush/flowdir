package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The flow store of one node: rollups, not raw flows.
//
// Every flow is added to the one-minute bucket of the time it ended, under a key of the exporter, both addresses, the
// service port, the protocol, the two interfaces and the two AS numbers.  The client's ephemeral port is dropped from the key
// (see normPorts): that is what keeps the number of keys at the number of conversations, not the number of connections.
// A bucket holds at most MaxKeys keys; a flow past that is added to one per-exporter "other" entry and counted (overflow), so a
// scan or a flood can use up no more than a bucket's worth of memory.
//
// A finished hour is compacted into an hourly bucket that keeps the HourTopK biggest keys (by bytes) and folds the rest into
// the same per-exporter "other" entries.  Minute buckets are kept MinuteHours, hourly ones HourDays (default: until the disk cap removes the oldest file).  Closed minutes are
// appended to files in the state directory (m-*.gob) and hourly buckets are written whole (h-*.gob), and both are read again
// at start, so a restart keeps the history.  A flow that arrives more than two minutes late is added in memory only.
//
// Flows are disjoint between nodes (an exporter's traffic is received by the node its packets reach), so the answers of the
// nodes add up: a cluster-wide report is the sum of the nodes' reports, with nothing counted twice.

// FlowConfig is settings.flow.  It is shared: every node collects the same way.  A pointer in Settings with omitempty, so a
// cluster that never used it has no "flow" key and its settings hash is unchanged.
type FlowConfig struct {
	Enabled bool `json:"enabled"`
	// Ports: NetFlow v5/v9 (default 2055), IPFIX (4739) and sFlow (6343).  0 = the default; -1 = not listened on.
	NetFlowPort int `json:"netflow_port,omitempty"`
	IPFIXPort   int `json:"ipfix_port,omitempty"`
	SFlowPort   int `json:"sflow_port,omitempty"`
	// Exporters are the senders accepted (everything else is dropped before a byte is decoded): a name and an address.  The
	// address is an IPv4 or IPv6 address, a network (10.9.0.0/16) or a host name that DNS resolves.  The name is what the
	// reports and the exporter= filter call it; a network's name stands for every address in it.
	Exporters []FlowExporterCfg `json:"exporters,omitempty"`
	// Caps (shared): the flow folder may use this percentage (0 = the default, 90) of the volume it is on, and the rollups this
	// percentage (0 = the default, 90) of the machine's memory (the cgroup limit when that is smaller).  At a cap the oldest
	// files, or the oldest buckets in memory, go first.  Each node applies them to its own volume and memory.
	DirMaxPercent int `json:"dir_max_percent,omitempty"`
	MemMaxPercent int `json:"mem_max_percent,omitempty"`
	// Limits.
	MaxKeys     int `json:"max_keys,omitempty"`      // per minute bucket; default 100000
	MinuteHours int `json:"minute_hours,omitempty"`  // minute buckets are kept this long; default 6
	HourDays    int `json:"hour_days,omitempty"`     // hourly buckets are kept this long; default 0: until the disk cap removes them
	HourTopK    int `json:"hour_top_keys,omitempty"` // keys kept per hourly bucket; default 20000
	// Dedupe: a flow that several exporters on its path all report is counted once in a report (see flow_query.go).  Absent = on;
	// false turns it off.  A report can ask either way with its own dedupe parameter.
	Dedupe *bool `json:"dedupe,omitempty"`
	// ChartHover: the Flow page's chart shows the values under the pointer.  Absent = on; false turns it off.  Only the page reads it.
	ChartHover *bool `json:"chart_hover,omitempty"`
	// Replicate keeps a copy of every node's closed minutes on the next node, so one node's history survives its loss.  Not built yet.
}

// FlowExporterCfg is one entry of settings.flow.exporters.
type FlowExporterCfg struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Disabled bool   `json:"disabled,omitempty"` // kept in the list, but its packets are refused
}

// on is whether the collector listens: settings.flow.enabled, or as soon as there is an exporter (the GUI has no switch for it).
func (c FlowConfig) on() bool { return c.Enabled || len(c.Exporters) > 0 }

func (c *FlowConfig) clone() *FlowConfig {
	if c == nil {
		return nil
	}
	d := *c
	d.Exporters = append([]FlowExporterCfg(nil), c.Exporters...)
	if len(d.Exporters) == 0 {
		d.Exporters = nil
	}
	if c.Dedupe != nil {
		v := *c.Dedupe
		d.Dedupe = &v
	}
	return &d
}

// dedupe is whether reports count a flow once when several exporters report it (on unless turned off).
func (c *FlowConfig) dedupe() bool { return c == nil || c.Dedupe == nil || *c.Dedupe }

func (c *FlowConfig) maxKeys() int     { return orDef(c.MaxKeys, 100000) }
func (c *FlowConfig) minuteHours() int { return orDef(c.MinuteHours, 6) }

// hourKeep is how long an hourly bucket is kept, in seconds; 0 is for ever (the disk cap, and the memory cap, decide).
func (c *FlowConfig) hourKeep() int64 { return int64(c.HourDays) * 86400 }
func (c *FlowConfig) hourTopK() int   { return orDef(c.HourTopK, 20000) }

func orDef(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

func (c *FlowConfig) port(v, def int) int {
	switch {
	case v < 0:
		return 0
	case v == 0:
		return def
	}
	return v
}

func (c *FlowConfig) ports() (nf, ipfix, sf int) {
	return c.port(c.NetFlowPort, 2055), c.port(c.IPFIXPort, 4739), c.port(c.SFlowPort, 6343)
}

// Validate refuses what cannot work.
func (c *FlowConfig) Validate() error {
	if c == nil {
		return nil
	}
	for _, p := range []int{c.NetFlowPort, c.IPFIXPort, c.SFlowPort} {
		if p > 65535 {
			return fmt.Errorf("flow: port %d", p)
		}
	}
	if c.DirMaxPercent < 0 || c.DirMaxPercent > 100 {
		return fmt.Errorf("flow: the disk cap is 1 to 100 percent (0 = the default, 90)")
	}
	if c.MemMaxPercent < 0 || c.MemMaxPercent > 100 {
		return fmt.Errorf("flow: the memory cap is 1 to 100 percent (0 = the default, 90)")
	}
	seen := map[string]bool{}
	for i, e := range c.Exporters {
		e.Name, e.Address = strings.TrimSpace(e.Name), strings.TrimSpace(e.Address)
		if e.Name == "" || e.Address == "" {
			return fmt.Errorf("flow: exporter %d needs a name and an address", i+1)
		}
		if len(e.Name) > 64 || strings.ContainsAny(e.Name, " \t,=()!&|") {
			return fmt.Errorf("flow: exporter name %q: up to 64 characters, no spaces or any of , = ( ) ! & |", e.Name)
		}
		if err := checkExporterAddr(e.Address); err != nil {
			return fmt.Errorf("flow: exporter %s: %v", e.Name, err)
		}
		if seen[strings.ToLower(e.Name)] {
			return fmt.Errorf("flow: exporter name %q is used twice", e.Name)
		}
		seen[strings.ToLower(e.Name)] = true
	}
	if c.MaxKeys < 0 || c.MinuteHours < 0 || c.HourDays < 0 || c.HourTopK < 0 || c.MaxKeys > 5000000 || c.HourTopK > 1000000 {
		return fmt.Errorf("flow: a limit is out of range")
	}
	return nil
}

// validFlowDir checks flow_dir: empty (the default), or an absolute path that is not the root.
func validFlowDir(d string) error {
	if d == "" {
		return nil
	}
	if strings.ContainsRune(d, 0) || !filepath.IsAbs(d) || filepath.Clean(d) == "/" {
		return fmt.Errorf("flow_dir: %q must be an absolute path to a folder (not /)", d)
	}
	return nil
}

// flowKey is what a rollup is keyed by.
type flowKey struct {
	Exp          netip.Addr
	Src, Dst     netip.Addr
	SPort, DPort uint16
	Proto        uint8
	InIf, OutIf  uint32
	SrcAS, DstAS uint32
}

// flowVal is what a key accumulates.
type flowVal struct{ Bytes, Packets, Flows uint64 }

func (v *flowVal) add(o flowVal) { v.Bytes += o.Bytes; v.Packets += o.Packets; v.Flows += o.Flows }

type flowBucket struct {
	TS    int64
	M     map[flowKey]flowVal
	Other flowVal // not keyed: what the key limit refused
	Trunc int     // keys folded into "other" by an hourly compaction
	saved bool
	// pend is what was added since the bucket was written (late flows, or flows after a restart that read the minute back): written as a second
	// record of the same minute, which Load adds to the first.
	pend *flowBucket
}

type flowEntry struct {
	K flowKey
	V flowVal
}

type flowFileRec struct {
	TS      int64
	Entries []flowEntry
	Trunc   int
}

// flowStats are this node's collector counters.
var flowStats struct {
	datagrams, records, bytes, badPackets, noTemplate, refused, overflow atomic.Uint64
}

// normPorts drops the ephemeral side: of two ports the larger is zeroed when it is 1024 or more.
func normPorts(f *FlowRec) (sp, dp uint16) {
	sp, dp = f.SrcPort, f.DstPort
	if f.Proto != 6 && f.Proto != 17 && f.Proto != 132 { // no ports in other protocols (ICMP type and code are in them)
		return 0, 0
	}
	switch {
	case sp > dp && sp >= 1024:
		sp = 0
	case dp > sp && dp >= 1024:
		dp = 0
	case sp == dp && sp >= 1024:
		sp, dp = 0, sp
	}
	return
}

type flowStore struct {
	mu   sync.RWMutex
	cfg  FlowConfig
	min  map[int64]*flowBucket
	hour map[int64]*flowBucket
	dir  string
	// dirErr is why dir was given up (Load could not make it), shown in the status.
	dirErr string
	now    func() time.Time

	// the cap on the folder (see enforceCapLocked)
	capPct, capMB int
	volSize       func(dir string) (uint64, error)
	curFile       string // the file being appended to: never removed by the cap
	dirBytes      uint64
	capBytes      uint64
	capped        uint64 // files removed by the cap since start
	capWarnAt     time.Time
	capNoVol      bool

	// the cap on memory (see enforceMemLocked)
	memPct, memMB int
	memTotal      func() uint64
	memBytes      uint64
	memCap        uint64
	memDropped    uint64 // buckets dropped by the cap since start
	memWarnAt     time.Time
	memNoTotal    bool

	// the writer: records are copied under mu and encoded, packed and written by its own goroutine, so a busy minute never holds
	// up the collector or a query.  The file of the current hour is the writer's alone.
	wq       chan flowWrite
	resolve  func([]netip.Addr, time.Duration) map[netip.Addr]string // reverse names, for the wildcards of a filter
	curMu    sync.Mutex                                              // guards curFile when the writer sets it
	wstart   sync.Once
	fileHour int64
	file     *os.File

	// diskHours are the hourly files in the folder: an hour the memory cap left out is read from its file when a report needs it.
	// idx says what each hour holds (flow_qpar.go), for the hours in memory and the ones that are only on disk.
	diskHours map[int64]string
	idxMu     sync.RWMutex
	idx       map[int64]*hourIdx
}

// flowWrite is one job of the writer: a minute record to append, an hourly file to replace, or (done set) a barrier.
type flowWrite struct {
	rec  flowFileRec
	hour int64
	path string        // set: an hourly file, written whole
	done chan struct{} // set: closed when every earlier job is on disk; the open file is closed too
}

// flowWriteQueue is how many records may wait for the writer.  When the disk cannot keep up the queue fills and the
// collector waits for it: a bounded memory is better than a growing one.
const flowWriteQueue = 8

func newFlowStore(dir string, cfg FlowConfig) *flowStore {
	return &flowStore{cfg: cfg, min: map[int64]*flowBucket{}, hour: map[int64]*flowBucket{}, dir: dir, now: time.Now, volSize: volumeSize, memTotal: machineMemory}
}

// volumeSize is the size of the volume dir is on.
func volumeSize(dir string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint64(st.Blocks) * uint64(st.Bsize), nil
}

const defaultFlowDirPercent = 90

// What the rollups cost in memory, per key and per bucket.  Measured with a map of 50 000 to 1 000 000 keys: 167 to 268 bytes a
// key (Go maps grow by doubling, so just after a doubling a key costs most); 220 is the working figure, an estimate.
const (
	flowKeyBytes    = 220
	flowBucketBytes = 256
	defaultMemPct   = 90
)

// machineMemory is the memory this process may use: the machine's, or the cgroup's limit when that is smaller.
func machineMemory() uint64 {
	var total uint64
	if b, err := os.ReadFile(procMeminfo); err == nil {
		total, _, _, _ = parseMeminfo(string(b))
	}
	if limit, _, ok := cgroupUsage(); ok && limit > 0 && (total == 0 || limit < total) {
		total = limit
	}
	return total
}

// SetMemCap sets the cap on memory: pct percent of the machine's memory (0 = 90), or mb megabytes when that is set.
func (s *flowStore) SetMemCap(pct, mb int) {
	s.mu.Lock()
	s.memPct, s.memMB = pct, mb
	s.mu.Unlock()
}

func (s *flowStore) memCapLocked() (uint64, bool) {
	if s.memMB > 0 {
		return uint64(s.memMB) << 20, true
	}
	pct := s.memPct
	if pct <= 0 {
		pct = defaultMemPct
	}
	t := s.memTotal()
	if t == 0 {
		return 0, false
	}
	return t / 100 * uint64(pct), true
}

// memEstimateLocked is what the buckets hold, as an estimate.
func (s *flowStore) memEstimateLocked() uint64 {
	var n uint64
	for _, b := range s.min {
		n += flowBucketBytes + uint64(len(b.M))*flowKeyBytes
	}
	for _, b := range s.hour {
		n += flowBucketBytes + uint64(len(b.M))*flowKeyBytes
	}
	return n
}

// enforceMemLocked keeps the rollups within the memory cap, first in, first out: the bucket whose span ended longest ago goes
// first (the minutes of an hour before the hourly bucket that sums them) until they fit.  The newest minute is kept.
func (s *flowStore) enforceMemLocked(now time.Time) {
	est := s.memEstimateLocked()
	s.memBytes = est
	limit, ok := s.memCapLocked()
	if !ok {
		if !s.memNoTotal {
			s.memNoTotal = true
			warnf("flow: cannot tell this machine's memory: the rollups have no memory cap (there is nothing to take the memory cap of)")
		}
		s.memCap = 0
		return
	}
	s.memNoTotal = false
	s.memCap = limit
	if est <= limit {
		return
	}
	type be struct {
		ts   int64
		end  int64
		hour bool
		cost uint64
	}
	var all []be
	var newest int64
	for t, b := range s.min {
		all = append(all, be{t, t + 60, false, flowBucketBytes + uint64(len(b.M))*flowKeyBytes})
		if t > newest {
			newest = t
		}
	}
	for t, b := range s.hour {
		all = append(all, be{t, t + 3600, true, flowBucketBytes + uint64(len(b.M))*flowKeyBytes})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].end != all[j].end {
			return all[i].end < all[j].end
		}
		if all[i].hour != all[j].hour {
			return !all[i].hour
		}
		return all[i].ts < all[j].ts
	})
	dropped := 0
	for _, e := range all {
		if est <= limit {
			break
		}
		if !e.hour && e.ts == newest {
			continue
		}
		if e.hour {
			delete(s.hour, e.ts)
		} else {
			delete(s.min, e.ts)
		}
		est -= e.cost
		dropped++
	}
	s.memBytes = est
	s.memDropped += uint64(dropped)
	if dropped > 0 && now.Sub(s.memWarnAt) > 10*time.Minute {
		s.memWarnAt = now
		warnf("flow: the rollups are over their memory cap of %d MB: dropped the %d oldest bucket(s) (further drops are not logged for 10 minutes)", limit>>20, dropped)
	}
}

// SetCap sets the cap on the folder: pct percent of the volume (0 = 90), or mb megabytes when that is set.
func (s *flowStore) SetCap(pct, mb int) {
	s.mu.Lock()
	s.capPct, s.capMB = pct, mb
	s.mu.Unlock()
}

// capLocked is the cap in bytes, or false when it cannot be worked out (the volume's size is unknown and no size is set).
func (s *flowStore) capLocked() (uint64, bool) {
	if s.capMB > 0 {
		return uint64(s.capMB) << 20, true
	}
	pct := s.capPct
	if pct <= 0 {
		pct = defaultFlowDirPercent
	}
	vol, err := s.volSize(s.dir)
	if err != nil || vol == 0 {
		return 0, false
	}
	return vol / 100 * uint64(pct), true
}

// enforceCapLocked keeps the folder within its cap, first in, first out: when the files add up to more, the oldest are
// deleted (a minute file before an hourly one of the same hour) until they fit.  The file being written is kept.
func (s *flowStore) enforceCapLocked(now time.Time) {
	if s.dir == "" {
		return
	}
	type fe struct {
		name string
		ts   int64
		hour bool
		size uint64
	}
	var files []fe
	var total uint64
	ents, _ := os.ReadDir(s.dir)
	for _, e := range ents {
		n := e.Name()
		hour := strings.HasPrefix(n, "h-")
		if e.IsDir() || !(hour || strings.HasPrefix(n, "m-")) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		var ts int64
		fmt.Sscanf(n[2:], "%d", &ts)
		files = append(files, fe{n, ts, hour, uint64(info.Size())})
		total += uint64(info.Size())
	}
	s.dirBytes = total
	limit, ok := s.capLocked()
	if !ok {
		if !s.capNoVol {
			s.capNoVol = true
			warnf("flow: cannot tell the size of the volume of %s: the folder has no cap (there is nothing to take the disk cap of)", s.dir)
		}
		s.capBytes = 0
		return
	}
	s.capNoVol = false
	s.capBytes = limit
	if total <= limit {
		return
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].ts != files[j].ts {
			return files[i].ts < files[j].ts
		}
		if files[i].hour != files[j].hour {
			return !files[i].hour
		}
		return files[i].name < files[j].name
	})
	removed := 0
	for _, f := range files {
		if total <= limit {
			break
		}
		if f.name == s.currentFile() {
			continue
		}
		if err := os.Remove(filepath.Join(s.dir, f.name)); err != nil {
			continue
		}
		total -= f.size
		removed++
		if f.hour { // the hour is gone from the disk: it is gone from the reports too, as it would be after a restart
			delete(s.hour, f.ts)
		}
	}
	s.dirBytes = total
	s.capped += uint64(removed)
	if removed > 0 && now.Sub(s.capWarnAt) > 10*time.Minute {
		s.capWarnAt = now
		warnf("flow: %s is over its cap of %d MB: removed the %d oldest file(s) (further removals are not logged for 10 minutes)", s.dir, limit>>20, removed)
	}
}

func (s *flowStore) SetConfig(c FlowConfig) {
	s.mu.Lock()
	s.cfg = c
	s.mu.Unlock()
}

func (s *flowStore) Add(f FlowRec) {
	now := s.now()
	t := f.Time
	if t.IsZero() || now.Sub(t) > time.Duration(s.cfg.minuteHours())*time.Hour || t.Sub(now) > 5*time.Minute {
		t = now
	}
	ts := t.Unix() / 60 * 60
	sp, dp := normPorts(&f)
	k := flowKey{Exp: f.Exporter, Src: f.Src, Dst: f.Dst, SPort: sp, DPort: dp, Proto: f.Proto, InIf: f.InIf, OutIf: f.OutIf, SrcAS: f.SrcAS, DstAS: f.DstAS}
	v := flowVal{f.Bytes, f.Packets, 1}
	s.mu.Lock()
	b := s.min[ts]
	if b == nil {
		b = &flowBucket{TS: ts, M: map[flowKey]flowVal{}}
		s.min[ts] = b
	}
	pk := k
	if cur, ok := b.M[k]; ok {
		cur.add(v)
		b.M[k] = cur
	} else if len(b.M) >= s.cfg.maxKeys() {
		ok := flowKey{Exp: f.Exporter}
		cur := b.M[ok]
		cur.add(v)
		b.M[ok] = cur
		flowStats.overflow.Add(1)
		pk = ok
	} else {
		b.M[k] = v
	}
	if b.saved {
		if b.pend == nil {
			b.pend = &flowBucket{TS: b.TS, M: map[flowKey]flowVal{}}
		}
		c := b.pend.M[pk]
		c.add(v)
		b.pend.M[pk] = c
	}
	s.mu.Unlock()
}

// Keys is how many keys the store holds, for the status.
func (s *flowStore) Keys() (minutes, hours, keys int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, b := range s.min {
		keys += len(b.M)
	}
	for _, b := range s.hour {
		keys += len(b.M)
	}
	return len(s.min), len(s.hour), keys
}

// Maintain persists closed minutes, compacts finished hours and drops what is past its retention.  It runs every minute.
func (s *flowStore) Maintain() {
	now := s.now()
	nowMin := now.Unix() / 60 * 60
	s.mu.Lock()
	defer s.mu.Unlock()
	// persist the minutes that are closed (older than two minutes)
	var ts []int64
	for t, b := range s.min {
		if (!b.saved || b.pend != nil) && t <= nowMin-120 {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	for _, t := range ts {
		s.persistMinuteLocked(s.min[t])
	}
	// compact the hours that are over (two minutes of grace for late flows)
	hours := map[int64]bool{}
	for t := range s.min {
		h := t / 3600 * 3600
		if h+3600 <= nowMin-120 && s.hour[h] == nil {
			hours[h] = true
		}
	}
	for h := range hours {
		s.compactLocked(h)
	}
	// retention
	for t := range s.min {
		if now.Unix()-t > int64(s.cfg.minuteHours())*3600 {
			delete(s.min, t)
		}
	}
	for t := range s.hour {
		if k := s.cfg.hourKeep(); k > 0 && now.Unix()-t > k {
			delete(s.hour, t)
		}
	}
	s.pruneFilesLocked(now)
	s.enforceCapLocked(now)
	s.enforceMemLocked(now)
}

func (s *flowStore) compactLocked(h int64) {
	hb := &flowBucket{TS: h, M: map[flowKey]flowVal{}}
	for t := h; t < h+3600; t += 60 {
		if b := s.min[t]; b != nil {
			for k, v := range b.M {
				cur := hb.M[k]
				cur.add(v)
				hb.M[k] = cur
			}
			hb.Other.add(b.Other)
		}
	}
	if k := s.cfg.hourTopK(); len(hb.M) > k {
		type kv struct {
			k flowKey
			v flowVal
		}
		all := make([]kv, 0, len(hb.M))
		for key, v := range hb.M {
			all = append(all, kv{key, v})
		}
		sort.Slice(all, func(i, j int) bool { return all[i].v.Bytes > all[j].v.Bytes })
		hb.M = make(map[flowKey]flowVal, k)
		for i, e := range all {
			if i < k {
				hb.M[e.k] = e.v
				continue
			}
			ok := flowKey{Exp: e.k.Exp}
			cur := hb.M[ok]
			cur.add(e.v)
			hb.M[ok] = cur
			hb.Trunc++
		}
	}
	s.hour[h] = hb
	s.idxSet(h, buildIdx(hb))
	prewarm(hb)
	if s.dir != "" {
		s.enqueue(flowWrite{rec: bucketRec(hb), path: filepath.Join(s.dir, fmt.Sprintf("h-%d.gob", h))})
	}
}

func bucketRec(b *flowBucket) flowFileRec {
	r := flowFileRec{TS: b.TS, Trunc: b.Trunc, Entries: make([]flowEntry, 0, len(b.M)+1)}
	for k, v := range b.M {
		r.Entries = append(r.Entries, flowEntry{k, v})
	}
	if b.Other != (flowVal{}) {
		r.Entries = append(r.Entries, flowEntry{flowKey{}, b.Other})
	}
	return r
}

func writeGobFile(path string, rec flowFileRec) error {
	fr, err := lzFrame(rec)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append([]byte(flowMagic), fr...), 0o600); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// enqueue hands a job to the writer, which is started with the first one.
func (s *flowStore) enqueue(j flowWrite) {
	s.wstart.Do(func() {
		s.wq = make(chan flowWrite, flowWriteQueue)
		go s.writer(s.wq)
	})
	s.wq <- j
}

func (s *flowStore) writer(q chan flowWrite) {
	for j := range q {
		switch {
		case j.done != nil:
			if s.file != nil {
				s.file.Close()
				s.file = nil
			}
			close(j.done)
		case j.path != "":
			if err := writeGobFile(j.path, j.rec); err != nil {
				warnf("flow: cannot write the hourly file: %v", err)
			}
		default:
			s.appendMinute(j)
		}
	}
}

// appendMinute appends one minute to the file of its hour (writer goroutine only).
func (s *flowStore) appendMinute(j flowWrite) {
	if s.file == nil || s.fileHour != j.hour {
		if s.file != nil {
			s.file.Close()
		}
		s.file = nil
		// every restart starts a new file, so a file is never appended to by two runs
		name := filepath.Join(s.dir, fmt.Sprintf("m-%d-%d.gob", j.hour, time.Now().UnixNano()))
		f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			warnf("flow: cannot open %s: %v", name, err)
			return
		}
		if _, err := f.WriteString(flowMagic); err != nil {
			warnf("flow: cannot write %s: %v", name, err)
			f.Close()
			return
		}
		s.file, s.fileHour = f, j.hour
		s.curMu.Lock() // not mu: the collector may hold mu while it waits for this goroutine
		s.curFile = filepath.Base(name)
		s.curMu.Unlock()
	}
	fr, err := lzFrame(j.rec)
	if err == nil {
		_, err = s.file.Write(fr)
	}
	if err != nil {
		warnf("flow: cannot write a minute: %v", err)
		s.file.Close()
		s.file = nil
	}
}

func (s *flowStore) currentFile() string {
	s.curMu.Lock()
	defer s.curMu.Unlock()
	return s.curFile
}

// persistMinuteLocked copies the minute for the writer; mu is held only for the copy.
func (s *flowStore) persistMinuteLocked(b *flowBucket) {
	out := b
	if b.saved { // written before: only what came after
		out = b.pend
	}
	b.saved, b.pend = true, nil
	if s.dir == "" || out == nil {
		return
	}
	s.enqueue(flowWrite{rec: bucketRec(out), hour: b.TS / 3600 * 3600})
}

func (s *flowStore) pruneFilesLocked(now time.Time) {
	if s.dir == "" {
		return
	}
	ents, _ := os.ReadDir(s.dir)
	dh := map[int64]string{}
	defer func() {
		s.diskHours = dh
		s.idxPrune(s.hour, dh)
	}()
	for _, e := range ents {
		n := e.Name()
		var kind byte
		var ts int64
		switch {
		case strings.HasPrefix(n, "m-"):
			kind = 'm'
			fmt.Sscanf(strings.TrimPrefix(n, "m-"), "%d", &ts)
		case strings.HasPrefix(n, "h-"):
			kind = 'h'
			fmt.Sscanf(strings.TrimPrefix(n, "h-"), "%d", &ts)
		default:
			continue
		}
		age := now.Unix() - ts
		if (kind == 'm' && age > int64(s.cfg.minuteHours())*3600+7200) || (kind == 'h' && s.cfg.hourKeep() > 0 && age > s.cfg.hourKeep()+7200) {
			os.Remove(filepath.Join(s.dir, n))
		} else if kind == 'h' && !strings.HasSuffix(n, ".tmp") {
			dh[ts] = filepath.Join(s.dir, n)
		}
	}
}

// Load reads the files of the state directory back.
func (s *flowStore) Load() {
	if s.dir == "" {
		return
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		errorf("flow: cannot use %s: %v (the rollups are kept in memory only)", s.dir, err)
		s.dirErr, s.dir = err.Error(), ""
		return
	}
	ents, _ := os.ReadDir(s.dir)
	now := s.now().Unix()
	s.mu.Lock()
	defer s.mu.Unlock()
	// newest files first, so that when the memory cap is reached it is the oldest history that stays on disk
	fileTS := func(n string) int64 {
		var ts int64
		if len(n) > 2 {
			fmt.Sscanf(n[2:], "%d", &ts)
		}
		return ts
	}
	sort.SliceStable(ents, func(i, j int) bool { return fileTS(ents[i].Name()) > fileTS(ents[j].Name()) })
	memLimit, haveLimit := s.memCapLocked()
	nm, nh := 0, 0
	s.diskHours = map[int64]string{}
	for _, e := range ents {
		if n := e.Name(); strings.HasPrefix(n, "h-") && !strings.HasSuffix(n, ".tmp") {
			if k := s.cfg.hourKeep(); k > 0 && now-fileTS(n) > k {
				continue
			}
			s.diskHours[fileTS(n)] = filepath.Join(s.dir, n)
		}
	}
	for _, e := range ents {
		if haveLimit && s.memEstimateLocked() > memLimit {
			infof("flow: stopped reading history back at the memory cap (%d MB); older files stay on disk", memLimit>>20)
			break
		}
		n := e.Name()
		isM, isH := strings.HasPrefix(n, "m-"), strings.HasPrefix(n, "h-")
		if !isM && !isH || strings.HasSuffix(n, ".tmp") {
			continue
		}
		f, err := os.Open(filepath.Join(s.dir, n))
		if err != nil {
			continue
		}
		readFlowRecs(f, func(r flowFileRec) {
			dst, keep := s.min, int64(s.cfg.minuteHours())*3600
			if isH {
				dst, keep = s.hour, s.cfg.hourKeep()
			}
			if keep > 0 && now-r.TS > keep {
				return
			}
			b := dst[r.TS]
			if b == nil {
				b = &flowBucket{TS: r.TS, M: map[flowKey]flowVal{}, saved: true}
				dst[r.TS] = b
			}
			b.Trunc += r.Trunc
			for _, en := range r.Entries {
				if en.K == (flowKey{}) {
					b.Other.add(en.V)
					continue
				}
				cur := b.M[en.K]
				cur.add(en.V)
				b.M[en.K] = cur
			}
			if isM {
				nm++
			} else {
				nh++
			}
		})
		f.Close()
	}
	for h, b := range s.hour {
		s.idxSet(h, buildIdx(b))
	}
	if nm+nh > 0 {
		infof("flow: read back %d minute and %d hourly buckets", nm, nh)
	}
	if left := len(s.diskHours) - len(s.hour); left > 0 {
		infof("flow: %d older hourly files stay on disk and are read when a report asks for them", left)
	}
}

// Close waits until everything handed to the writer is on disk, then closes the open file.
func (s *flowStore) Close() {
	s.mu.Lock()
	started := s.wq != nil
	s.mu.Unlock()
	if !started {
		return
	}
	done := make(chan struct{})
	s.wq <- flowWrite{done: done}
	<-done
}

// flushAll persists every minute not yet written, the open ones too (at a clean stop).
func (s *flowStore) flushAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	var ts []int64
	for t, b := range s.min {
		if !b.saved || b.pend != nil {
			ts = append(ts, t)
		}
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i] < ts[j] })
	for _, t := range ts {
		s.persistMinuteLocked(s.min[t])
	}
}

// checkExporterAddr accepts an address, a network or a host name (letters, digits, dots and hyphens).
func checkExporterAddr(a string) error {
	if _, err := netip.ParsePrefix(a); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return nil
	}
	if len(a) > 253 || strings.Trim(strings.ToLower(a), "abcdefghijklmnopqrstuvwxyz0123456789.-_") != "" || strings.HasPrefix(a, ".") || strings.HasPrefix(a, "-") {
		return fmt.Errorf("%q is not an address, a network or a host name", a)
	}
	return nil
}
