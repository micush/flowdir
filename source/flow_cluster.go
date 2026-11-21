package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"time"
)

// The flow collector in the cluster.
//
// Two things cross the peer channel (the signed TLS channel of clusternet.go, with the same pinning and HMAC as everything else):
//
//   - Templates and sampling rates.  A node that learns a template (or a changed one) tells every other node within a moment
//     (/cluster/flow/templates), and a node that starts asks the others for everything they have.  An exporter whose packets
//     move to another node, because the VIP moved or the anycast path changed, is therefore read at once.
//
//   - Reports.  Every node holds the flows of the exporters whose packets reached it, and no flow is on two nodes, so a report
//     is the sum of the nodes' reports (/cluster/flow/query): the node that is asked fans the question out, adds the answers up
//     and cuts the list.  A node that does not answer is named in the answer, and what it held is missing from the totals.

type flowTmplMsg struct {
	Templates []*FlowTemplate `json:"templates,omitempty"`
	Rates     []FlowRate      `json:"rates,omitempty"`
	IfNames   []FlowIfName    `json:"ifnames,omitempty"`
}

type flowQueryMsg struct {
	Op    string    `json:"op"` // query, exporters or status
	Query FlowQuery `json:"query"`
}

type flowQueryReply struct {
	Answer    *FlowAnswer        `json:"answer,omitempty"`
	Exporters []FlowExporterInfo `json:"exporters,omitempty"`
	Status    *FlowNodeStatus    `json:"status,omitempty"`
	Digest    *FlowDigest        `json:"digest,omitempty"`
	Exps      *flowExps          `json:"exps,omitempty"`
}

func (c *Cluster) registerFlowRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /cluster/flow/templates", c.peerAuth(c.handleFlowTemplates))
	mux.HandleFunc("GET /cluster/flow/templates", c.peerAuth(c.handleFlowTemplatesGet))
	mux.HandleFunc("POST /cluster/flow/query", c.peerAuth(c.handleFlowQuery))
}

func (c *Cluster) handleFlowTemplates(rw http.ResponseWriter, r *http.Request, caller ClusterPeer, body []byte) {
	var m flowTmplMsg
	if json.Unmarshal(body, &m) != nil || flowSvc == nil {
		jsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	flowSvc.tmpls.Import(m.Templates, m.Rates)
	flowSvc.tmpls.ImportIfNames(m.IfNames)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write([]byte(`{}`))
}

func (c *Cluster) handleFlowTemplatesGet(rw http.ResponseWriter, r *http.Request, caller ClusterPeer, _ []byte) {
	if flowSvc == nil {
		jsonError(rw, http.StatusServiceUnavailable, "no flow collector")
		return
	}
	ts, rs := flowSvc.tmpls.Snapshot()
	b, _ := json.Marshal(flowTmplMsg{Templates: ts, Rates: rs, IfNames: flowSvc.tmpls.SnapshotIfNames()})
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(b)
}

func (c *Cluster) handleFlowQuery(rw http.ResponseWriter, r *http.Request, caller ClusterPeer, body []byte) {
	var m flowQueryMsg
	if json.Unmarshal(body, &m) != nil || flowSvc == nil {
		jsonError(rw, http.StatusBadRequest, "bad request")
		return
	}
	var rep flowQueryReply
	switch m.Op {
	case "query":
		if err := m.Query.Validate(); err != nil {
			jsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
		a := flowSvc.store.Query(m.Query)
		rep.Answer = &a
	case "digest":
		if err := m.Query.Validate(); err != nil {
			jsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
		d := flowSvc.store.Digest(m.Query)
		rep.Digest = &d
	case "exps":
		if err := m.Query.Validate(); err != nil {
			jsonError(rw, http.StatusBadRequest, err.Error())
			return
		}
		e := flowSvc.store.rangeExporters(m.Query)
		rep.Exps = &e
	case "exporters":
		rep.Exporters = flowSvc.Exporters()
	case "status":
		st := flowSvc.Status()
		rep.Status = &st
	default:
		jsonError(rw, http.StatusBadRequest, "bad op")
		return
	}
	b, _ := json.Marshal(rep)
	rw.Header().Set("Content-Type", "application/json")
	rw.Write(b)
}

// otherPeers are the members besides this node.
func (s *flowService) otherPeers() []ClusterPeer {
	if s.mg == nil || s.mg.cl == nil || !s.mg.cl.Enabled() {
		return nil
	}
	return s.mg.cl.node.Snapshot().Peers
}

// replicate sends what this node learns to the others, in batches.
func (s *flowService) replicate(ctx context.Context) {
	var msg flowTmplMsg
	flush := func() {
		if len(msg.Templates)+len(msg.Rates)+len(msg.IfNames) == 0 {
			return
		}
		m := msg
		msg = flowTmplMsg{}
		if peers := s.otherPeers(); len(peers) > 0 {
			s.mg.cl.broadcast(peers, "/cluster/flow/templates", m)
		}
	}
	t := time.NewTicker(300 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case l := <-s.learnCh:
			if l.T != nil {
				msg.Templates = append(msg.Templates, l.T)
			}
			if l.R != nil {
				msg.Rates = append(msg.Rates, *l.R)
			}
			if l.N != nil {
				msg.IfNames = append(msg.IfNames, *l.N)
			}
			if len(msg.Templates)+len(msg.Rates)+len(msg.IfNames) >= 200 {
				flush()
			}
		case <-t.C:
			flush()
		}
	}
}

// pullTemplates asks the other nodes for their templates once, when this node starts (or later, when it first has peers).
func (s *flowService) pullTemplates(ctx context.Context) {
	done := map[string]bool{}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	deadline := time.Now().Add(10 * time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if time.Now().After(deadline) {
			return
		}
		for _, p := range s.otherPeers() {
			if done[p.NodeID] {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, 8*time.Second)
			var m flowTmplMsg
			err := s.mg.cl.call(cctx, p, "GET", "/cluster/flow/templates", nil, &m, 8*time.Second)
			cancel()
			if err != nil {
				continue
			}
			s.tmpls.Import(m.Templates, m.Rates)
			s.tmpls.ImportIfNames(m.IfNames)
			done[p.NodeID] = true
			infof("flow: took %d templates from %s", len(m.Templates), p.Addr)
		}
	}
}

// NodeError says which node could not answer.
type NodeError struct {
	Node  string `json:"node"`
	Error string `json:"error"`
}

// fan asks every node (this one directly) and returns the answers.  An unreachable node is reported, not fatal.
func (s *flowService) fan(ctx context.Context, m flowQueryMsg) (reps []flowQueryReply, errs []NodeError, nodes int) {
	local := func() flowQueryReply {
		var r flowQueryReply
		switch m.Op {
		case "query":
			a := s.store.Query(m.Query)
			r.Answer = &a
		case "digest":
			d := s.store.Digest(m.Query)
			r.Digest = &d
		case "exps":
			e := s.store.rangeExporters(m.Query)
			r.Exps = &e
		case "exporters":
			r.Exporters = s.Exporters()
		case "status":
			st := s.Status()
			r.Status = &st
		}
		return r
	}
	peers := s.otherPeers()
	var mu sync.Mutex
	var wg sync.WaitGroup
	reps = append(reps, local())
	for _, p := range peers {
		wg.Add(1)
		go func(p ClusterPeer) {
			defer wg.Done()
			to := flowRoundTimeout(m.Query.From, m.Query.To)
			cctx, cancel := context.WithTimeout(ctx, to)
			defer cancel()
			var r flowQueryReply
			err := s.mg.cl.call(cctx, p, "POST", "/cluster/flow/query", m, &r, to)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, NodeError{p.Addr, err.Error()})
				return
			}
			reps = append(reps, r)
		}(p)
	}
	wg.Wait()
	sort.Slice(errs, func(i, j int) bool { return errs[i].Node < errs[j].Node })
	return reps, errs, len(peers) + 1
}

// oneExporter asks every node which exporters it has for the range, and says whether the cluster as a whole has at most one.  A node
// that does not answer, or does not know (an hour only on disk that has not been looked at yet, or an older version), makes the
// answer no.
func (s *flowService) oneExporter(ctx context.Context, q FlowQuery) bool {
	q.Losers = nil
	reps, errs, _ := s.fan(ctx, flowQueryMsg{Op: "exps", Query: q})
	if len(errs) > 0 {
		return false
	}
	seen := map[netip.Addr]struct{}{}
	for _, r := range reps {
		if r.Exps == nil || r.Exps.Unknown {
			return false
		}
		for _, a := range r.Exps.Addrs {
			seen[a] = struct{}{}
		}
	}
	return len(seen) <= 1
}

// Report is the cluster-wide answer to a query.
func (s *flowService) Report(ctx context.Context, q FlowQuery) (FlowAnswer, []NodeError, int) {
	deduped, cut := false, false
	var errs0 []NodeError
	if dedupes(q) && s.oneExporter(ctx, q) {
		// one exporter in the whole cluster for this range: no flow is reported twice, so there is nothing to deduplicate
		deduped = true
	} else if dedupes(q) {
		// the first round: what every exporter counted of every flow, to find the ones several exporters reported
		q.Losers = nil
		dr, e0, _ := s.fan(ctx, flowQueryMsg{Op: "digest", Query: q})
		errs0 = e0
		var ds []FlowDigest
		for _, r := range dr {
			if r.Digest != nil {
				ds = append(ds, *r.Digest)
				cut = cut || r.Digest.Cut
			}
		}
		q.Losers = chooseLosers(ds)
		deduped = true
	}
	reps, errs, n := s.fan(ctx, flowQueryMsg{Op: "query", Query: q})
	if len(errs) == 0 {
		errs = errs0
	}
	var parts []FlowAnswer
	for _, r := range reps {
		if r.Answer != nil {
			parts = append(parts, *r.Answer)
		}
	}
	a := mergeFlowAnswers(parts, q)
	a.Deduped, a.DedupeCut = deduped, deduped && cut
	return a, errs, n
}

// AllExporters lists the exporters every node hears from.  An exporter heard on two nodes is listed twice (with the node).
func (s *flowService) AllExporters(ctx context.Context) ([]FlowExporterInfo, []NodeError) {
	reps, errs, _ := s.fan(ctx, flowQueryMsg{Op: "exporters"})
	var out []FlowExporterInfo
	for _, r := range reps {
		out = append(out, r.Exporters...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr != out[j].Addr {
			return out[i].Addr < out[j].Addr
		}
		return out[i].Node < out[j].Node
	})
	return out, errs
}

func (s *flowService) AllStatus(ctx context.Context) ([]FlowNodeStatus, []NodeError) {
	reps, errs, _ := s.fan(ctx, flowQueryMsg{Op: "status"})
	var out []FlowNodeStatus
	for _, r := range reps {
		if r.Status != nil {
			out = append(out, *r.Status)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out, errs
}
