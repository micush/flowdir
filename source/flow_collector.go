package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// The flow collector of a node: UDP listeners for NetFlow v5/v9 (2055), IPFIX (4739) and sFlow (6343) on the addresses of the
// gateways (the VIPs, the further addresses and the anycast addresses) and on the node's extra addresses, like the MCP
// listeners (mcplisten.go): IP_FREEBIND, so a socket exists before the address does, and a set that follows the configuration.
//
// An exporter is pointed at a gateway address.  The cluster then does what it does for everything else behind a VIP: the
// controller answers for the address with one node's MAC (or BGP/OSPF routes the anycast address to the nearest node), the
// exporter's datagrams reach that node, and when it fails they reach another.  The new node can read them at once because the
// templates were replicated while the first one was alive (flow_cluster.go).
//
// Who may send: the entries of settings.flow.exporters (a name and an address, a network or a host name).  Everyone else is
// counted (refused) and dropped before a byte is decoded.

type flowListenKey struct {
	addr netip.Addr
	port int
}

type flowExporter struct {
	First, Last time.Time
	Datagrams   uint64
	Records     uint64
	Format      string
	To          map[netip.Addr]time.Time // the local addresses its datagrams were sent to, and when the last one came (a few at most)
}

// FlowExporterInfo is one exporter in the status.
type FlowExporterInfo struct {
	Addr      string `json:"addr"`
	Name      string `json:"name,omitempty"`
	Format    string `json:"format"`
	First     int64  `json:"first_seen"`
	Last      int64  `json:"last_seen"`
	Datagrams uint64 `json:"datagrams"`
	Records   uint64 `json:"records"`
	Rate      uint32 `json:"sampling_rate,omitempty"`
	Node      string `json:"node,omitempty"`
	// To is where the exporter sends to: the addresses of this node its datagrams came in on in the last 15 minutes (a gateway's
	// address, or an anycast one).  The Topology page draws the exporter on the gateway that holds one of them.
	To []string `json:"to,omitempty"`
	// Host is the host part of the name the address reverse-looks-up to (sw1 for sw1.example.com): what Topology calls the exporter.  Empty
	// while it is not known (the lookup runs in the background) or when the address has no name.
	Host string `json:"host,omitempty"`
	// RDNS is the whole name (sw1.example.com), empty when Host is.
	RDNS string `json:"rdns,omitempty"`
}

type flowService struct {
	dnsBusy   atomic.Bool // a background reverse lookup of exporters is running
	tmplDirty atomic.Bool // a template or rate was learned since templates.json was written
	sup       *Supervisor
	mg        *Mgmt
	store     *flowStore
	tmpls     *flowTemplates

	mu        sync.Mutex
	ls        map[flowListenKey]net.PacketConn
	failed    map[flowListenKey]string
	exporters map[netip.Addr]*flowExporter
	refusedAt map[netip.Addr]time.Time
	cancel    context.CancelFunc

	expMu   sync.RWMutex
	expNets []flowExpNet              // the addresses the configured exporters stand for (settings.flow.exporters)
	expDNS  map[string][]netip.Prefix // a host name of an exporter -> the addresses it resolved to last

	learnCh chan flowLearn
	dns     *flowDNS
}

type flowLearn struct {
	T *FlowTemplate
	R *FlowRate
	N *FlowIfName
}

// flowSvc is this node's collector (nil in a test that has none).
var flowSvc *flowService

func newFlowService(sup *Supervisor, mg *Mgmt) *flowService {
	dir := ""
	if mg != nil && mg.stateDir != "" {
		dir = filepath.Join(mg.stateDir, "flow")
	}
	if sup != nil {
		if dc := sup.config(); dc != nil && dc.FlowDir != "" {
			dir = filepath.Clean(dc.FlowDir)
		}
	}
	s := &flowService{
		sup: sup, mg: mg, store: newFlowStore(dir, FlowConfig{}), tmpls: newFlowTemplates(),
		ls: map[flowListenKey]net.PacketConn{}, failed: map[flowListenKey]string{}, exporters: map[netip.Addr]*flowExporter{},
		refusedAt: map[netip.Addr]time.Time{}, expDNS: map[string][]netip.Prefix{}, learnCh: make(chan flowLearn, 4096), dns: newFlowDNS(),
	}
	s.store.resolve = s.dns.names
	s.tmpls.OnLearn = func(t *FlowTemplate, r *FlowRate) {
		s.tmplDirty.Store(true)
		select {
		case s.learnCh <- flowLearn{T: t, R: r}:
		default: // full: the next full pull (a node that restarts) repairs what is missed
		}
	}
	s.tmpls.OnLearnIfName = func(n FlowIfName) {
		s.tmplDirty.Store(true)
		select {
		case s.learnCh <- flowLearn{N: &n}:
		default:
		}
	}
	return s
}

func (s *flowService) config() FlowConfig {
	if s.sup == nil {
		return FlowConfig{}
	}
	dc := s.sup.config()
	if dc == nil || dc.Settings.Flow == nil {
		return FlowConfig{}
	}
	return *dc.Settings.Flow
}

// applyCaps hands the shared disk and memory caps (settings.flow) to the store.
func (s *flowService) applyCaps() {
	c := s.config()
	s.store.SetCap(c.DirMaxPercent, 0)
	s.store.SetMemCap(c.MemMaxPercent, 0)
	applyGoMemLimit(machineMemory(), c.MemMaxPercent)
}

// Start opens the store and runs the loops.
func (s *flowService) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.mu.Lock()
	s.cancel = cancel
	s.mu.Unlock()
	s.store.SetConfig(s.config())
	s.applyCaps()
	s.store.Load()
	s.loadTemplates()
	go s.loop(ctx, 3*time.Second, func() { s.reconcile(); s.syncExporters() })
	go s.loop(ctx, time.Minute, func() {
		s.store.SetConfig(s.config())
		s.applyCaps()
		s.store.Maintain()
		s.saveTemplates()
	})
	go s.loop(ctx, time.Minute, s.resolveExporters)
	go s.replicate(ctx)
	go s.pullTemplates(ctx)
}

func (s *flowService) loop(ctx context.Context, every time.Duration, f func()) {
	f()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			f()
		}
	}
}

func (s *flowService) Stop() {
	s.mu.Lock()
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	for k, c := range s.ls {
		c.Close()
		delete(s.ls, k)
	}
	s.mu.Unlock()
	s.store.Maintain() // persist what is closed
	s.store.flushAll()
	s.store.Close()
	s.saveTemplates()
}

// reconcile makes the sockets match the configuration.
func (s *flowService) reconcile() {
	cfg := s.config()
	var want []flowListenKey
	if cfg.on() {
		nf, ipfix, sf := cfg.ports()
		var addrs []netip.Addr
		dc := s.sup.config()
		if dc != nil {
			addrs = gatewayAddrs(dc, true)
			for _, l := range dc.FlowListen {
				if a, err := netip.ParseAddr(l); err == nil {
					addrs = append(addrs, a.Unmap())
				}
			}
		}
		// Nothing says where to listen (no flow_listen): take every address of this node, so an exporter can send to the node's
		// own address as well as to a gateway's.  The wildcard also receives what is sent to a gateway address this node holds, so
		// those need no socket of their own (a specific bind next to a wildcard one would fail anyway).
		if dc == nil || len(dc.FlowListen) == 0 {
			addrs = []netip.Addr{netip.IPv4Unspecified(), netip.IPv6Unspecified()}
		}
		seen := map[flowListenKey]bool{}
		for _, a := range addrs {
			for _, p := range []int{nf, ipfix, sf} {
				k := flowListenKey{a, p}
				if p > 0 && !seen[k] {
					seen[k] = true
					want = append(want, k)
				}
			}
		}
	}
	wanted := map[flowListenKey]bool{}
	for _, k := range want {
		wanted[k] = true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel == nil {
		return
	}
	for k, c := range s.ls {
		if !wanted[k] {
			c.Close()
			delete(s.ls, k)
			infof("flow: stopped listening on %s", net.JoinHostPort(k.addr.String(), strconv.Itoa(k.port)))
		}
	}
	for k := range s.failed {
		if !wanted[k] {
			delete(s.failed, k)
		}
	}
	for _, k := range want {
		if s.ls[k] != nil {
			continue
		}
		network := "udp4"
		if k.addr.Is6() {
			network = "udp6"
		}
		hp := net.JoinHostPort(k.addr.String(), strconv.Itoa(k.port))
		lc := net.ListenConfig{Control: flowListenControl}
		pc, err := lc.ListenPacket(context.Background(), network, hp)
		if err != nil {
			if s.failed[k] != err.Error() && !errors.Is(err, syscall.EAFNOSUPPORT) { // a host without IPv6 has nothing to listen on there
				errorf("flow: cannot listen on %s: %v", hp, err)
			}
			s.failed[k] = err.Error()
			continue
		}
		if u, ok := pc.(*net.UDPConn); ok {
			u.SetReadBuffer(8 << 20)
		}
		delete(s.failed, k)
		s.ls[k] = pc
		infof("flow: listening on udp %s", hp)
		go s.read(pc)
	}
}

func (s *flowService) read(pc net.PacketConn) {
	u, ok := pc.(*net.UDPConn)
	if !ok {
		return
	}
	buf := make([]byte, 65536)
	oob := make([]byte, 256)
	for {
		n, oobn, _, ap, err := u.ReadMsgUDPAddrPort(buf, oob)
		if err != nil {
			return // closed
		}
		s.handleTo(ap.Addr().Unmap(), pktinfoDst(oob[:oobn]), buf[:n], time.Now())
	}
}

// handle takes one datagram (whose destination is not known).
func (s *flowService) handle(exp netip.Addr, b []byte, now time.Time) {
	s.handleTo(exp, netip.Addr{}, b, now)
}

// handleTo takes one datagram that came in on the local address dst (invalid when that is not known).
func (s *flowService) handleTo(exp, dst netip.Addr, b []byte, now time.Time) {
	defer func() {
		if r := recover(); r != nil {
			flowStats.badPackets.Add(1)
			errorf("flow: decoder panic from %s: %v", exp, r)
		}
	}()
	flowStats.datagrams.Add(1)
	flowStats.bytes.Add(uint64(len(b)))
	if !s.allowed(exp) {
		flowStats.refused.Add(1)
		s.noteRefused(exp)
		return
	}
	recs, err := s.tmpls.DecodeFlow(exp, b, now)
	if err != nil && len(recs) == 0 {
		flowStats.badPackets.Add(1)
	}
	for i := range recs {
		s.store.Add(recs[i])
	}
	flowStats.records.Add(uint64(len(recs)))
	s.noteExporter(exp, dst, b, len(recs), now)
}

func (s *flowService) noteRefused(exp netip.Addr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.refusedAt) > 1000 {
		s.refusedAt = map[netip.Addr]time.Time{}
	}
	if t, ok := s.refusedAt[exp]; !ok || time.Since(t) > 10*time.Minute {
		s.refusedAt[exp] = time.Now()
		warnf("flow: export from %s refused: not in settings.flow.exporters", exp)
	}
}

func formatOf(b []byte) string {
	if len(b) < 4 {
		return "?"
	}
	if b[0] == 0 && b[1] == 0 {
		return "sflow5"
	}
	switch binary.BigEndian.Uint16(b) {
	case 5:
		return "netflow5"
	case 9:
		return "netflow9"
	case 10:
		return "ipfix"
	}
	return "?"
}

func (s *flowService) noteExporter(exp, dst netip.Addr, b []byte, recs int, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.exporters[exp]
	if e == nil {
		if len(s.exporters) >= 4096 {
			return
		}
		e = &flowExporter{First: now}
		s.exporters[exp] = e
		infof("flow: new exporter %s (%s)", exp, formatOf(b))
	}
	e.Last, e.Format = now, formatOf(b)
	if dst.IsValid() {
		if e.To == nil {
			e.To = map[netip.Addr]time.Time{}
		}
		if _, ok := e.To[dst]; ok || len(e.To) < 8 {
			e.To[dst] = now
		}
	}
	e.Datagrams++
	e.Records += uint64(recs)
}

// flowExpNet is an address or network an exporter entry stands for, with the entry's name.
type flowExpNet struct {
	p    netip.Prefix
	name string
}

// allowed says whether exp may export to us: it is in an entry of settings.flow.exporters that is not disabled.
func (s *flowService) allowed(exp netip.Addr) bool {
	return s.exporterName(exp) != ""
}

// syncExporters makes the accepted addresses match the configuration (every few seconds, so a change takes effect at once).
// A host name uses what resolveExporters last found for it.
func (s *flowService) syncExporters() {
	cfg := s.config()
	var out []flowExpNet
	s.expMu.RLock()
	dns := s.expDNS
	s.expMu.RUnlock()
	for _, e := range cfg.Exporters {
		if e.Disabled {
			continue
		}
		if p, err := netip.ParsePrefix(e.Address); err == nil {
			out = append(out, flowExpNet{p.Masked(), e.Name})
		} else if a, err := netip.ParseAddr(e.Address); err == nil {
			a = a.Unmap()
			out = append(out, flowExpNet{netip.PrefixFrom(a, a.BitLen()), e.Name})
		} else {
			for _, p := range dns[strings.ToLower(e.Address)] {
				out = append(out, flowExpNet{p, e.Name})
			}
		}
	}
	s.expMu.Lock()
	s.expNets = out
	s.expMu.Unlock()
}

// resolveExporters looks up the host names among the exporters (every minute: a name may move) and syncs.
func (s *flowService) resolveExporters() {
	cfg := s.config()
	m := map[string][]netip.Prefix{}
	for _, e := range cfg.Exporters {
		if e.Disabled {
			continue
		}
		if _, err := netip.ParsePrefix(e.Address); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(e.Address); err == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", e.Address)
		cancel()
		var ps []netip.Prefix
		for _, a := range ips {
			a = a.Unmap()
			ps = append(ps, netip.PrefixFrom(a, a.BitLen()))
		}
		if len(ps) == 0 { // a lookup that failed keeps what the name resolved to before
			s.expMu.RLock()
			ps = s.expDNS[strings.ToLower(e.Address)]
			s.expMu.RUnlock()
		}
		m[strings.ToLower(e.Address)] = ps
	}
	s.expMu.Lock()
	s.expDNS = m
	s.expMu.Unlock()
	s.syncExporters()
}

// exporterName is the name of the entry whose address or network holds a ("" when none does; the narrowest network wins).
func (s *flowService) exporterName(a netip.Addr) string {
	s.expMu.RLock()
	defer s.expMu.RUnlock()
	best, bits := "", -1
	for _, n := range s.expNets {
		if n.p.Contains(a) && n.p.Bits() > bits {
			best, bits = n.name, n.p.Bits()
		}
	}
	return best
}

// exporterPrefixes finds the addresses of an entry by its name (case ignored).
func (s *flowService) exporterPrefixes(name string) []netip.Prefix {
	s.expMu.RLock()
	defer s.expMu.RUnlock()
	var out []netip.Prefix
	for _, n := range s.expNets {
		if strings.EqualFold(n.name, name) {
			out = append(out, n.p)
		}
	}
	return out
}

// Exporters lists what this node has heard from.
func (s *flowService) Exporters() []FlowExporterInfo {
	node := selfHost()
	s.mu.Lock()
	out := make([]FlowExporterInfo, 0, len(s.exporters))
	for a, e := range s.exporters {
		info := FlowExporterInfo{Addr: a.String(), Format: e.Format, First: e.First.Unix(), Last: e.Last.Unix(), Datagrams: e.Datagrams, Records: e.Records, Node: node}
		for d, t := range e.To {
			if time.Since(t) < 15*time.Minute {
				info.To = append(info.To, d.String())
			}
		}
		sort.Strings(info.To)
		out = append(out, info)
	}
	s.mu.Unlock()
	var unknown []netip.Addr
	for i := range out {
		a, _ := netip.ParseAddr(out[i].Addr)
		if name, known := s.peekName(a); known {
			out[i].Host, out[i].RDNS = hostPart(name), name
		} else {
			unknown = append(unknown, a)
		}
		out[i].Name = s.exporterName(a)
		out[i].Rate = s.tmpls.rateAny(a)
	}
	if len(unknown) > 0 && s.dns != nil && s.dnsBusy.CompareAndSwap(false, true) {
		go func() { // the names are looked up in the background; the next call has them
			defer s.dnsBusy.Store(false)
			s.dns.names(unknown, 8*time.Second)
		}()
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// hostPart is the first label of a name: sw1 for sw1.example.com.
func hostPart(name string) string {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if i := strings.IndexByte(name, '.'); i > 0 {
		return name[:i]
	}
	return name
}

// FlowNodeStatus is the state of one node's collector.
type FlowNodeStatus struct {
	Node       string   `json:"node"`
	Enabled    bool     `json:"enabled"`
	Listening  []string `json:"listening"`
	Failed     []string `json:"failed,omitempty"`
	Dir        string   `json:"dir,omitempty"`         // where the rollups are kept (empty: memory only)
	DefaultDir string   `json:"default_dir,omitempty"` // where they are kept when flow_dir is not set (the state directory's flow folder)
	DirError   string   `json:"dir_error,omitempty"`   // why they are not
	DirBytes   uint64   `json:"dir_bytes,omitempty"`   // what the folder holds now
	DirCap     uint64   `json:"dir_cap_bytes,omitempty"`
	CapRemoved uint64   `json:"cap_removed_files,omitempty"` // files deleted (oldest first) to stay within the cap
	MemBytes   uint64   `json:"mem_bytes_estimate,omitempty"`
	MemCap     uint64   `json:"mem_cap_bytes,omitempty"`
	MemDropped uint64   `json:"mem_dropped_buckets,omitempty"` // buckets dropped (oldest first) to stay within the memory cap
	Datagrams  uint64   `json:"datagrams"`
	Records    uint64   `json:"records"`
	Bytes      uint64   `json:"datagram_bytes"`
	Bad        uint64   `json:"bad_packets"`
	NoTemplate uint64   `json:"no_template"`
	Refused    uint64   `json:"refused"`
	Overflow   uint64   `json:"overflow"`
	MinuteBkts int      `json:"minute_buckets"`
	HourBkts   int      `json:"hour_buckets"`
	Keys       int      `json:"keys"`
	Templates  int      `json:"templates"`
	Oldest     int64    `json:"oldest,omitempty"` // time of the oldest bucket this node holds (range=all starts at the oldest of all nodes)
}

func (s *flowService) Status() FlowNodeStatus {
	cfg := s.config()
	st := FlowNodeStatus{Node: selfHost(), Enabled: cfg.on(), Listening: []string{}, Oldest: s.store.oldest()}
	s.mu.Lock()
	for k := range s.ls {
		st.Listening = append(st.Listening, "udp "+net.JoinHostPort(k.addr.String(), strconv.Itoa(k.port)))
	}
	for k, why := range s.failed {
		st.Failed = append(st.Failed, net.JoinHostPort(k.addr.String(), strconv.Itoa(k.port))+": "+why)
	}
	s.mu.Unlock()
	sort.Strings(st.Listening)
	sort.Strings(st.Failed)
	st.Datagrams, st.Records, st.Bytes = flowStats.datagrams.Load(), flowStats.records.Load(), flowStats.bytes.Load()
	st.Bad, st.NoTemplate, st.Refused, st.Overflow = flowStats.badPackets.Load(), flowStats.noTemplate.Load(), flowStats.refused.Load(), flowStats.overflow.Load()
	s.store.mu.RLock()
	st.Dir, st.DirError, st.DirBytes, st.DirCap, st.CapRemoved = s.store.dir, s.store.dirErr, s.store.dirBytes, s.store.capBytes, s.store.capped
	st.MemBytes, st.MemCap, st.MemDropped = s.store.memBytes, s.store.memCap, s.store.memDropped
	s.store.mu.RUnlock()
	if s.mg != nil && s.mg.stateDir != "" {
		st.DefaultDir = filepath.Join(s.mg.stateDir, "flow")
	}
	st.MinuteBkts, st.HourBkts, st.Keys = s.store.Keys()
	ts, _ := s.tmpls.Snapshot()
	st.Templates = len(ts)
	return st
}

func (s *flowService) peekName(a netip.Addr) (string, bool) {
	if s.dns == nil {
		return "", false
	}
	return s.dns.peek(a)
}
