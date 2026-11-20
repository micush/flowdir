package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// The flow reports: /api/flow/{report,exporters,status}, and the MCP tools on top of them (flow_top, flow_timeseries,
// flow_exporters, flow_status).  A report is asked of any node; it fans out (flow_cluster.go) and comes back with names put
// to the numbers: the name an exporter was given on Configure ▸ Exporters, the DNS name of a host, the service a port is.

// freebindControlUDP is freebindControl for UDP sockets.
func freebindControlUDP(network, address string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		if network == "udp6" {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, soIPv6Freebind, 1)
		} else {
			serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, soIPFreebind, 1)
		}
	})
	if err != nil {
		return err
	}
	return serr
}

var flowProtoNames = map[uint8]string{1: "icmp", 2: "igmp", 4: "ipip", 6: "tcp", 17: "udp", 41: "ipv6", 47: "gre", 50: "esp", 51: "ah", 58: "icmpv6", 88: "eigrp", 89: "ospf", 103: "pim", 112: "vrrp", 132: "sctp"}

var flowServiceNames = map[uint16]string{
	20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http", 88: "kerberos",
	110: "pop3", 123: "ntp", 135: "msrpc", 137: "netbios", 138: "netbios", 139: "netbios", 143: "imap", 161: "snmp", 162: "snmptrap", 179: "bgp",
	389: "ldap", 443: "https", 445: "smb", 465: "smtps", 500: "ike", 514: "syslog", 515: "lpd", 587: "submission", 636: "ldaps", 853: "dns-tls",
	873: "rsync", 993: "imaps", 995: "pop3s", 1194: "openvpn", 1433: "mssql", 1521: "oracle", 1701: "l2tp", 1723: "pptp", 1812: "radius", 1813: "radius-acct",
	2049: "nfs", 3128: "squid", 3306: "mysql", 3389: "rdp", 4500: "ipsec-nat", 4789: "vxlan", 5060: "sip", 5061: "sips", 5432: "postgres", 5601: "kibana",
	5671: "amqps", 5672: "amqp", 5900: "vnc", 6379: "redis", 6443: "kube-api", 6343: "sflow", 8080: "http-alt", 8443: "https-alt", 9092: "kafka",
	9200: "elasticsearch", 9100: "jetdirect", 11211: "memcached", 27017: "mongodb", 2055: "netflow", 4739: "ipfix", 51820: "wireguard",
}

func flowProtoName(p uint8) string {
	if n, ok := flowProtoNames[p]; ok {
		return n
	}
	return strconv.Itoa(int(p))
}

// ── reverse DNS ──────────────────────────────────────────────────────────────────────────────────────────────────

type flowDNS struct {
	mu sync.Mutex
	m  map[netip.Addr]dnsEnt
}

type dnsEnt struct {
	name string
	at   time.Time
}

func newFlowDNS() *flowDNS { return &flowDNS{m: map[netip.Addr]dnsEnt{}} }

// peek is what is known of an address without asking anyone: its name (empty when it has none or is not known), and whether it is known.
func (d *flowDNS) peek(a netip.Addr) (string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e, ok := d.m[a]
	return e.name, ok && time.Since(e.at) < 30*time.Minute
}

// names looks addresses up, a few at a time, within the budget; what is not answered in time is left out (and tried again next time).
func (d *flowDNS) names(addrs []netip.Addr, budget time.Duration) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	var todo []netip.Addr
	d.mu.Lock()
	for _, a := range addrs {
		if !a.IsValid() {
			continue
		}
		if e, ok := d.m[a]; ok && time.Since(e.at) < 30*time.Minute {
			if e.name != "" {
				out[a] = e.name
			}
			continue
		}
		todo = append(todo, a)
	}
	d.mu.Unlock()
	if len(todo) == 0 {
		return out
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	sem := make(chan struct{}, 16)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, a := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, lc := context.WithTimeout(ctx, 500*time.Millisecond)
			defer lc()
			names, err := net.DefaultResolver.LookupAddr(lctx, a.String())
			name := ""
			if err == nil && len(names) > 0 {
				name = strings.TrimSuffix(names[0], ".")
			}
			if err != nil && ctx.Err() != nil {
				return // out of time: not an answer
			}
			d.mu.Lock()
			if len(d.m) > 20000 {
				d.m = map[netip.Addr]dnsEnt{}
			}
			d.m[a] = dnsEnt{name, time.Now()}
			d.mu.Unlock()
			if name != "" {
				mu.Lock()
				out[a] = name
				mu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	return out
}

// ── request parsing ──────────────────────────────────────────────────────────────────────────────────────────────

func parseFlowDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return time.Hour, nil
	}
	mult := map[byte]time.Duration{'m': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour, 'y': 365 * 24 * time.Hour}
	if m, ok := mult[s[len(s)-1]]; ok {
		n, err := strconv.Atoi(s[:len(s)-1])
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q: use 15m, 1h, 1d, 7d, 1y or all", s)
		}
		return time.Duration(n) * m, nil
	}
	return 0, fmt.Errorf("%q: use 15m, 1h, 1d, 7d, 1y or all", s)
}

func parseFlowTime(s string) (int64, error) {
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, fmt.Errorf("time %q: unix seconds or RFC 3339", s)
	}
	return t.Unix(), nil
}

func (s *flowService) prefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range splitList(list) {
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", e)
		cancel()
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("%q is not an address, a network or a name that resolves", e)
		}
		for _, a := range ips {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

func parseFlowPorts(list string) ([]uint16, error) {
	var out []uint16
	for _, e := range splitList(list) {
		if n, err := strconv.Atoi(e); err == nil && n >= 0 && n <= 65535 {
			out = append(out, uint16(n))
			continue
		}
		found := false
		for p, name := range flowServiceNames {
			if strings.EqualFold(name, e) {
				out = append(out, p)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("port %q: a number or a well-known service name", e)
		}
	}
	return out, nil
}

func parseFlowProtos(list string) ([]uint8, error) {
	var out []uint8
	for _, e := range splitList(list) {
		if n, err := strconv.Atoi(e); err == nil && n >= 0 && n <= 255 {
			out = append(out, uint8(n))
			continue
		}
		found := false
		for p, name := range flowProtoNames {
			if strings.EqualFold(name, e) {
				out = append(out, p)
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("protocol %q: tcp, udp, icmp, ... or a number", e)
		}
	}
	return out, nil
}

func parseUint32s(list string) ([]uint32, error) {
	var out []uint32
	for _, e := range splitList(list) {
		e = strings.TrimPrefix(strings.ToUpper(e), "AS")
		n, err := strconv.ParseUint(e, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%q is not a number", e)
		}
		out = append(out, uint32(n))
	}
	return out, nil
}

// parseFlowQuery turns the parameters of a request into a query.
var flowFilterKeys = []string{"exporter", "host", "src", "dst", "port", "proto", "interface", "as"}

// exporterTerm reads exporter=: an exporter's name, an address or a network, several separated by commas.
func (s *flowService) exporterTerm(val string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, e := range splitList(val) {
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		ps := s.exporterPrefixes(e)
		if len(ps) == 0 {
			return nil, fmt.Errorf("exporter %q: not the name of an exporter, an address or a network", e)
		}
		out = append(out, ps...)
	}
	return out, nil
}

// prefixesGlobs is prefixes for a list that may hold wildcards: 10.1.1.* becomes a prefix, the others (*.cox.net) stay patterns.
func (s *flowService) prefixesGlobs(list string) ([]netip.Prefix, []string, error) {
	plain, ps, globs := splitGlobs(splitList(list))
	if len(plain) > 0 {
		more, err := s.prefixes(strings.Join(plain, ","))
		if err != nil {
			return nil, nil, err
		}
		ps = append(ps, more...)
	}
	return ps, globs, nil
}

// filterTerm adds one filter, key=value, to f: the values (separated by commas) are alternatives.
func (s *flowService) filterTerm(f *FlowFilter, key, val string) error {
	var err error
	switch key {
	case "exporter":
		ps, perr := s.exporterTerm(val)
		if perr != nil {
			return perr
		}
		f.Exporters = append(f.Exporters, ps...)
	case "host":
		f.Hosts, f.HostGlobs, err = s.prefixesGlobs(val)
	case "src":
		f.Src, f.SrcGlobs, err = s.prefixesGlobs(val)
	case "dst":
		f.Dst, f.DstGlobs, err = s.prefixesGlobs(val)
	case "port":
		f.Ports, err = parseFlowPorts(val)
	case "proto":
		f.Protos, err = parseFlowProtos(val)
	case "interface":
		f.Ifs, err = parseUint32s(val)
	case "as":
		f.AS, err = parseUint32s(val)
	default:
		return fmt.Errorf("%s: not a filter (%s)", key, strings.Join(flowFilterKeys, ", "))
	}
	return err
}

// parseFlowExpr reads a filter with AND, OR and NOT: terms are name=value (host=10.0.0.5, port=443,53, exporter=sw1; several values
// are alternatives), a bare number is a port, anything else bare (address, prefix, name) is a host; ! or NOT in front of a term or a bracket negates it; AND binds tighter
// than OR; two terms side by side are joined by AND; brackets group.  host, src and dst take wildcards: 10.1.1.* (a prefix), *.cox.net (a name).  "host=10.0.0.5 AND !port=53", "(src=10.1.0.0/16 OR dst=10.1.0.0/16) port=443".
func (s *flowService) parseFlowExpr(text string) (*FlowExpr, error) {
	var toks []string
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n':
			i++
		case c == '(' || c == ')' || c == '!':
			toks = append(toks, string(c))
			i++
		default:
			j := i
			for j < len(text) && !strings.ContainsRune(" \t\n()", rune(text[j])) {
				j++
			}
			toks = append(toks, text[i:j])
			i = j
		}
	}
	pos := 0
	peek := func() string {
		if pos < len(toks) {
			return toks[pos]
		}
		return ""
	}
	isOp := func(t, w string) bool {
		return strings.EqualFold(t, w) || (w == "and" && t == "&&") || (w == "or" && t == "||")
	}
	var parseOr func(depth int) (*FlowExpr, error)
	var parseNot func(depth int) (*FlowExpr, error)
	parseNot = func(depth int) (*FlowExpr, error) {
		if depth > maxExprDepth {
			return nil, fmt.Errorf("filter: too deeply nested")
		}
		t := peek()
		switch {
		case t == "":
			return nil, fmt.Errorf("filter: a term is missing at the end")
		case t == "!" || isOp(t, "not"):
			pos++
			k, err := parseNot(depth + 1)
			if err != nil {
				return nil, err
			}
			return &FlowExpr{Op: "not", Kids: []*FlowExpr{k}}, nil
		case t == "(":
			pos++
			e, err := parseOr(depth + 1)
			if err != nil {
				return nil, err
			}
			if peek() != ")" {
				return nil, fmt.Errorf("filter: a ) is missing")
			}
			pos++
			return e, nil
		case t == ")" || isOp(t, "and") || isOp(t, "or"):
			return nil, fmt.Errorf("filter: a term is missing before %q", t)
		}
		pos++
		key, val, ok := strings.Cut(t, "=")
		if !ok && strings.Trim(t, "0123456789,") == "" {
			// only digits (and commas): a port
			for _, e := range splitList(t) {
				if n, err := strconv.Atoi(e); err != nil || n < 0 || n > 65535 {
					return nil, fmt.Errorf("filter: %q is not a port (0-65535)", e)
				}
			}
			key, val = "port", t
		} else if !ok {
			if !strings.Contains(t, "*") {
				if _, err := s.prefixes(t); err != nil {
					return nil, fmt.Errorf("filter: %q is not name=value, a number (a port) or an address", t)
				}
			}
			key, val = "host", t
		}
		var f FlowFilter
		if err := s.filterTerm(&f, strings.ToLower(key), val); err != nil {
			return nil, fmt.Errorf("filter: %v", err)
		}
		if f.empty() {
			return nil, fmt.Errorf("filter: %q has no value", t)
		}
		return &FlowExpr{Op: "term", Term: &f}, nil
	}
	parseAnd := func(depth int) (*FlowExpr, error) {
		first, err := parseNot(depth)
		if err != nil {
			return nil, err
		}
		kids := []*FlowExpr{first}
		for {
			t := peek()
			if isOp(t, "and") {
				pos++
			} else if t == "" || t == ")" || isOp(t, "or") {
				break
			}
			k, err := parseNot(depth)
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
		}
		if len(kids) == 1 {
			return first, nil
		}
		return &FlowExpr{Op: "and", Kids: kids}, nil
	}
	parseOr = func(depth int) (*FlowExpr, error) {
		first, err := parseAnd(depth)
		if err != nil {
			return nil, err
		}
		kids := []*FlowExpr{first}
		for isOp(peek(), "or") {
			pos++
			k, err := parseAnd(depth)
			if err != nil {
				return nil, err
			}
			kids = append(kids, k)
		}
		if len(kids) == 1 {
			return first, nil
		}
		return &FlowExpr{Op: "or", Kids: kids}, nil
	}
	e, err := parseOr(0)
	if err != nil {
		return nil, err
	}
	if pos < len(toks) {
		return nil, fmt.Errorf("filter: unexpected %q", toks[pos])
	}
	return e, nil
}

func (s *flowService) parseFlowQuery(v url.Values, series bool) (FlowQuery, error) {
	q := FlowQuery{By: v.Get("by"), Metric: v.Get("metric")}
	if q.By == "" && !series {
		q.By = "conversation"
	}
	q.Limit, _ = strconv.Atoi(v.Get("limit"))
	fc := s.config()
	q.NoDedupe = !fc.dedupe()
	switch strings.ToLower(v.Get("dedupe")) {
	case "":
	case "on", "1", "true", "yes":
		q.NoDedupe = false
	case "off", "0", "false", "no":
		q.NoDedupe = true
	default:
		return q, fmt.Errorf("dedupe: on or off")
	}
	now := time.Now()
	if v.Get("from") != "" || v.Get("to") != "" {
		var err error
		q.To = now.Unix()/60*60 + 60
		if v.Get("to") != "" {
			if q.To, err = parseFlowTime(v.Get("to")); err != nil {
				return q, err
			}
		}
		if v.Get("from") == "" {
			return q, fmt.Errorf("from: needed with to")
		}
		if q.From, err = parseFlowTime(v.Get("from")); err != nil {
			return q, err
		}
	} else {
		q.To = now.Unix()/60*60 + 60
		if strings.EqualFold(strings.TrimSpace(v.Get("range")), "all") { // as far back as the data of any node goes
			q.From = s.oldestAll()
			if q.From == 0 || q.To-q.From < 3600 {
				q.From = q.To - 3600
			}
		} else {
			d, err := parseFlowDuration(v.Get("range"))
			if err != nil {
				return q, err
			}
			q.From = q.To - int64(d/time.Second)
		}
	}
	if series {
		if st := v.Get("step"); st != "" {
			d, err := parseFlowDuration(st)
			if err != nil {
				return q, err
			}
			q.Step = int(d / time.Second)
		} else { // about 60 points
			q.Step = int((q.To-q.From)/60/60) * 60
			if q.Step < 60 {
				q.Step = 60
			}
		}
	}
	f := &q.Filter
	for _, key := range flowFilterKeys {
		if val := v.Get(key); val != "" {
			if err := s.filterTerm(f, key, val); err != nil {
				return q, err
			}
		}
	}
	if x := strings.TrimSpace(v.Get("filter")); x != "" {
		e, err := s.parseFlowExpr(x)
		if err != nil {
			return q, err
		}
		f.Expr = e
	}
	return q, q.Validate()
}

// ── answers for people ───────────────────────────────────────────────────────────────────────────────────────────

// dress puts names, shares and rates to the rows of a merged answer.
func (s *flowService) dress(a *FlowAnswer, q FlowQuery) {
	secs := float64(q.To - q.From)
	var addrs []netip.Addr
	for _, r := range a.Rows {
		for _, k := range []string{"src", "dst", "host", "a", "b"} {
			if x, err := netip.ParseAddr(r.Key[k]); err == nil {
				addrs = append(addrs, x)
			}
		}
	}
	dns := s.dns.names(addrs, 1500*time.Millisecond)
	totalM := metricOfRow(a.Total, q.Metric)
	for i := range a.Rows {
		r := &a.Rows[i]
		names := map[string]string{}
		for _, k := range []string{"src", "dst", "host", "a", "b"} {
			if x, err := netip.ParseAddr(r.Key[k]); err == nil {
				if n := dns[x]; n != "" {
					names[k] = n
				}
			}
		}
		if e, ok := r.Key["exporter"]; ok {
			if x, err := netip.ParseAddr(e); err == nil {
				if n := s.exporterName(x); n != "" {
					names["exporter"] = n
				}
			}
		}
		if p, ok := r.Key["proto"]; ok {
			n, _ := strconv.Atoi(p)
			names["proto"] = flowProtoName(uint8(n))
			if pt, ok := r.Key["port"]; ok && (n == 6 || n == 17) {
				pn, _ := strconv.Atoi(pt)
				if svc := flowServiceNames[uint16(pn)]; svc != "" {
					names["port"] = svc
				}
			}
		}
		if len(names) > 0 {
			r.Names = names
		}
		if totalM > 0 {
			r.Share = float64(int(float64(metricOfRow(*r, q.Metric))/float64(totalM)*10000)) / 100
		}
		if secs > 0 {
			r.Bps = float64(int(float64(r.Bytes)*8/secs*10)) / 10
		}
	}
	if secs > 0 {
		a.Total.Bps = float64(int(float64(a.Total.Bytes)*8/secs*10)) / 10
	}
}

type flowReply struct {
	From       int64        `json:"from"`
	To         int64        `json:"to"`
	By         string       `json:"by,omitempty"`
	Metric     string       `json:"metric"`
	Nodes      int          `json:"nodes"`
	NodeErrors []NodeError  `json:"node_errors,omitempty"`
	Total      FlowRow      `json:"total"`
	Other      *FlowRow     `json:"other,omitempty"`
	Rows       []FlowRow    `json:"rows,omitempty"`
	Series     []FlowSeries `json:"series,omitempty"`
	Step       int          `json:"step_sec,omitempty"`
	Approx     bool         `json:"approximate,omitempty"`
	Cut        bool         `json:"lists_cut,omitempty"`
	DedupeCut  bool         `json:"dedupe_cut,omitempty"`
	Deduped    bool         `json:"deduplicated,omitempty"` // a flow several exporters reported is counted once (dedupe=off adds them)
	Resolution string       `json:"resolution,omitempty"`
	Note       string       `json:"note,omitempty"`
}

func (w *WebServer) flowGate(rw http.ResponseWriter, s *session) bool {
	if flowSvc == nil {
		jsonError(rw, http.StatusServiceUnavailable, "this node has no flow collector")
		return false
	}
	return true
}

func (w *WebServer) handleFlowReport(rw http.ResponseWriter, r *http.Request, s *session) {
	if !w.flowGate(rw, s) {
		return
	}
	series := r.URL.Query().Get("series") == "1"
	q, err := flowSvc.parseFlowQuery(r.URL.Query(), series)
	if err != nil {
		jsonError(rw, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), flowReportTimeout(q))
	defer cancel()
	rep := flowSvc.buildReply(ctx, q)
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": rep})
}

func (w *WebServer) handleFlowExporters(rw http.ResponseWriter, r *http.Request, s *session) {
	if !w.flowGate(rw, s) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	ex, errs := flowSvc.AllExporters(ctx)
	if ex == nil {
		ex = []FlowExporterInfo{}
	}
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"exporters": ex, "node_errors": errs}})
}

func (w *WebServer) handleFlowStatus(rw http.ResponseWriter, r *http.Request, s *session) {
	if !w.flowGate(rw, s) {
		return
	}
	if r.URL.Query().Get("local") == "1" { // this node only (the Settings page reads the folder in use)
		writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"nodes": []FlowNodeStatus{flowSvc.Status()}}})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	st, errs := flowSvc.AllStatus(ctx)
	writeJSON(rw, http.StatusOK, map[string]any{"ok": true, "data": map[string]any{"nodes": st, "node_errors": errs}})
}

// ── MCP tools ────────────────────────────────────────────────────────────────────────────────────────────────────

var flowReportProps = []mcpProp{
	{name: "range", typ: "string", desc: "How far back: 15m, 1h (default), 6h, 1d, 7d, 30d, 90d, 1y, or all (as far back as the data goes: the disk cap decides).  Or give from and to (unix seconds or RFC 3339)."},
	{name: "from", typ: "string", desc: "Start of the range (instead of range)."},
	{name: "to", typ: "string", desc: "End of the range, default now."},
	{name: "metric", typ: "string", desc: "What to rank by: bytes (default), packets or flows.", enum: []string{"bytes", "packets", "flows"}},
	{name: "limit", typ: "integer", desc: "How many rows, default 20, at most 1000."},
	{name: "exporter", typ: "string", desc: "Only flows seen by these exporters: exporter names (as on Configure ▸ Exporters), addresses or networks, comma separated."},
	{name: "host", typ: "string", desc: "Only flows to or from these hosts: addresses, networks (10.1.0.0/16) or names, comma separated."},
	{name: "src", typ: "string", desc: "Only flows from these hosts or networks."},
	{name: "dst", typ: "string", desc: "Only flows to these hosts or networks."},
	{name: "port", typ: "string", desc: "Only this service port (either side): a number or a name (https, dns, ssh)."},
	{name: "proto", typ: "string", desc: "Only this protocol: tcp, udp, icmp, gre, esp, ospf ... or a number."},
	{name: "interface", typ: "string", desc: "Only flows in or out of this interface index (ifIndex), usually together with exporter."},
	{name: "as", typ: "string", desc: "Only flows from or to this AS number."},
	{name: "filter", typ: "string", desc: "Wildcards work in host, src and dst: 10.1.1.* (a /24), 10.1.*.* (a /16), *.example.com (DNS names). A filter with AND, OR, NOT (or !) and brackets, added to the filters above: terms are name=value (exporter, host, src, dst, port, proto, interface, as; commas make alternatives; a bare number is a port, any other bare word a host). Example: (src=10.1.0.0/16 OR dst=10.1.0.0/16) AND port=443 AND !host=10.1.1.1."},
	{name: "dedupe", typ: "string", desc: "on or off.  A flow that several exporters report (a path of switches, a switch and a firewall) is counted once, as the exporter that saw most of it reports it; off adds every exporter's report.  Default: the setting flow.dedupe (on).  Not applied when grouping by exporter or interface.", enum: []string{"on", "off"}},
}

func flowQS(c *mcpCtx, extra map[string]string) string {
	v := url.Values{}
	for _, p := range flowReportProps {
		if s := c.str(p.name); s != "" {
			v.Set(p.name, s)
		}
	}
	for _, k := range []string{"by", "step"} {
		if s := c.str(k); s != "" {
			v.Set(k, s)
		}
	}
	for k, x := range extra {
		v.Set(k, x)
	}
	return v.Encode()
}

// flowMCPTools are the flow tools, added to the list in mcp.go's init.
func flowMCPTools() []mcpTool {
	return []mcpTool{
		{name: "flow_top", title: "Flow report: top talkers",
			desc: "What the network carried, from the NetFlow, IPFIX and sFlow the cluster collects: the biggest entries by bytes, packets or flows over a range, grouped by `by`. " +
				"conversation (pairs of hosts, default), flow (source, destination, protocol and service port), src, dst, host (a host in either role), service (protocol and port), protocol, exporter, " +
				"interface (an exporter's interfaces, in and out, by ifIndex), src_as, dst_as. Each row has bytes, packets, flows (sampling already applied), share_pct of everything that matched and the average bits per second, with names where known (device, DNS name, service). " +
				"The answer adds up every node; node_errors names a node that did not answer. Narrow with exporter, host, src, dst, port, proto, interface and as. Hourly rollups answer long ranges and keep only the biggest keys (approximate says so).",
			noNode: true,
			props:  append([]mcpProp{{name: "by", typ: "string", desc: "Group by: conversation, flow, src, dst, host, service, protocol, exporter, interface, src_as, dst_as.", enum: flowGroupings}}, flowReportProps...),
			run: func(c *mcpCtx) (any, error) {
				b, err := c.get("/api/flow/report?" + flowQS(c, nil))
				return asAny(b), err
			}},
		{name: "flow_timeseries", title: "Flow report: traffic over time",
			desc: "Traffic over time: points of bytes, packets and flows for everything that matches, and, with `by`, for each of its biggest groups (the same groupings as flow_top). " +
				"step is the width of a point (default: about 60 points over the range; at least 1m; ranges that need hourly rollups give hourly points). Use it to see when something started, how a link filled up, or whether a host's traffic is steady.",
			noNode: true,
			props: append([]mcpProp{
				{name: "by", typ: "string", desc: "Also one series for each of the biggest of these groups.", enum: flowGroupings},
				{name: "step", typ: "string", desc: "Width of a point: 1m, 5m, 1h ..."},
			}, flowReportProps...),
			run: func(c *mcpCtx) (any, error) {
				b, err := c.get("/api/flow/report?" + flowQS(c, map[string]string{"series": "1"}))
				return asAny(b), err
			}},
		{name: "flow_exporters", title: "Flow exporters",
			desc:   "The exporters sending flows to the cluster: address, the name it was given on Configure ▸ Exporters, format (netflow5, netflow9, ipfix, sflow5), when first and last heard, datagrams and records, the sampling rate, and which node receives them.",
			noNode: true,
			run: func(c *mcpCtx) (any, error) {
				b, err := c.get("/api/flow/exporters")
				return asAny(b), err
			}},
		{name: "flow_status", title: "Flow collector status",
			desc:   "The state of the flow collector on every node: what it listens on, datagrams and records received, bad or refused packets, data that arrived before its template (no_template), flows over the key limit (overflow), what is stored and how many templates it knows.",
			noNode: true,
			run: func(c *mcpCtx) (any, error) {
				b, err := c.get("/api/flow/status")
				return asAny(b), err
			}},
	}
}

// buildReply asks the cluster and puts the answer in the form the API, the MCP tools and the CLI share.
func (s *flowService) buildReply(ctx context.Context, q FlowQuery) flowReply {
	a, errs, n := s.Report(ctx, q)
	s.dress(&a, q)
	rep := flowReply{From: q.From, To: q.To, By: q.By, Metric: firstNonEmpty(q.Metric, "bytes"), Nodes: n, NodeErrors: errs, Total: a.Total,
		Rows: a.Rows, Series: a.Series, Step: q.Step, Approx: a.Approx, Cut: a.Cut, Deduped: a.Deduped, DedupeCut: a.DedupeCut, Resolution: a.Resolved}
	if a.Other.Flows > 0 {
		o := a.Other
		rep.Other = &o
	}
	switch {
	case len(errs) > 0:
		rep.Note = fmt.Sprintf("%d of %d nodes did not answer: what they hold is missing from the totals", len(errs), n)
	case a.DedupeCut:
		rep.Note = "deduplication weighed only each node's biggest 100000 flows: smaller ones seen by exporters on different nodes may be counted twice"
	case a.Approx:
		rep.Note = "hourly rollups were used for part of the range and they keep only the biggest keys: small entries are folded into 'other'"
	case a.Total.Flows == 0:
		rep.Note = "no flows in this range (see flow_status: is anything exporting here?)"
	}
	return rep
}

// oldestAll is the time of the oldest bucket on any node of the cluster (this node's when the others cannot be asked, or are of
// a version that does not report it).
func (s *flowService) oldestAll() int64 {
	o := s.store.oldest()
	if s.mg == nil || s.mg.cl == nil || len(s.otherPeers()) == 0 {
		return o
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	sts, _ := s.AllStatus(ctx)
	for _, st := range sts {
		if st.Oldest > 0 && (o == 0 || st.Oldest < o) {
			o = st.Oldest
		}
	}
	return o
}
