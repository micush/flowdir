package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// The command line of the flow collector:
//
//	--flow                                  the collector on every node: what it listens on, counters, and the exporters
//	--flow-top BY [--flow-args "k=v&k=v"]   a report; BY is conversation, flow, src, dst, host, service, protocol, exporter,
//	                                        interface, src_as or dst_as; the arguments are those of the API and the MCP tools:
//	                                        range=1h metric=bytes limit=20 exporter=sw1 host=10.0.0.5 src= dst= port=https proto=tcp
//	                                        interface=12 as=64512 from= to= dedupe=on|off
//	                                        filter="(src=10.1.0.0/16 OR dst=10.1.0.0/16) AND !port=53"   (AND, OR, NOT or !, brackets)

type flowOpArgs struct {
	Q      string `json:"q"`
	Series bool   `json:"series,omitempty"`
}

// FlowOpReport is a report for the CLI, as the daemon builds it.
func (m *Mgmt) FlowOpReport(a flowOpArgs) (any, error) {
	if flowSvc == nil {
		return nil, fmt.Errorf("no flow collector in this process")
	}
	v, err := url.ParseQuery(a.Q)
	if err != nil {
		return nil, fmt.Errorf("arguments: %v", err)
	}
	q, err := flowSvc.parseFlowQuery(v, a.Series)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), flowReportTimeout(q))
	defer cancel()
	rep := flowSvc.buildReply(ctx, q)
	return rep, nil
}

func (m *Mgmt) FlowOpStatus() (any, error) {
	if flowSvc == nil {
		return nil, fmt.Errorf("no flow collector in this process")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, errs := flowSvc.AllStatus(ctx)
	ex, errs2 := flowSvc.AllExporters(ctx)
	return map[string]any{"nodes": st, "exporters": ex, "node_errors": append(errs, errs2...)}, nil
}

// rowLabel is a row's key as a line: names beside the values.
func rowLabel(by string, r FlowRow) []string {
	nm := func(k string) string {
		if n := r.Names[k]; n != "" && n != r.Key[k] {
			return r.Key[k] + " (" + n + ")"
		}
		return r.Key[k]
	}
	switch by {
	case "conversation":
		return []string{nm("a"), nm("b")}
	case "flow":
		return []string{nm("src"), nm("dst"), r.Names["proto"] + "/" + firstNonEmpty(r.Names["port"], r.Key["port"])}
	case "service":
		return []string{r.Names["proto"], firstNonEmpty(r.Names["port"], r.Key["port"])}
	case "protocol":
		return []string{r.Names["proto"]}
	case "interface":
		return []string{nm("exporter"), "if " + r.Key["ifindex"], r.Key["direction"]}
	case "exporter":
		return []string{nm("exporter")}
	case "host", "src", "dst":
		return []string{nm(by)}
	}
	return []string{r.Key["as"]}
}

func headerFor(by string) []string {
	switch by {
	case "conversation":
		return []string{"HOST A", "HOST B"}
	case "flow":
		return []string{"SOURCE", "DESTINATION", "SERVICE"}
	case "service":
		return []string{"PROTO", "PORT"}
	case "protocol":
		return []string{"PROTO"}
	case "interface":
		return []string{"EXPORTER", "INTERFACE", "DIR"}
	case "exporter":
		return []string{"EXPORTER"}
	case "host":
		return []string{"HOST"}
	case "src":
		return []string{"SOURCE"}
	case "dst":
		return []string{"DESTINATION"}
	}
	return []string{"AS"}
}

func runFlow(sock string, f *cliFlags) {
	if by := *f.flowTop; by != "" {
		q := *f.flowArgs
		if !strings.Contains(q, "by=") {
			if q != "" {
				q += "&"
			}
			q += "by=" + url.QueryEscape(by)
		}
		var rep flowReply
		decode(op(sock, "flow.report", flowOpArgs{Q: q}), &rep)
		from, to := time.Unix(rep.From, 0), time.Unix(rep.To, 0)
		fmt.Printf("%s to %s, by %s, ranked by %s; %d node(s)\n", from.Format("2006-01-02 15:04"), to.Format("2006-01-02 15:04"), rep.By, rep.Metric, rep.Nodes)
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintf(w, "%s\tBYTES\tPACKETS\tFLOWS\tSHARE\tAVG RATE\n", strings.Join(headerFor(rep.By), "\t"))
		for _, r := range rep.Rows {
			fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%.1f%%\t%s\n", strings.Join(rowLabel(rep.By, r), "\t"), humanBytes(r.Bytes), r.Packets, r.Flows, r.Share, humanBits(r.Bps))
		}
		w.Flush()
		fmt.Printf("total: %s, %d packets, %d flows, avg %s\n", humanBytes(rep.Total.Bytes), rep.Total.Packets, rep.Total.Flows, humanBits(rep.Total.Bps))
		if rep.Other != nil {
			fmt.Printf("not in a row (folded by a key limit): %s, %d flows\n", humanBytes(rep.Other.Bytes), rep.Other.Flows)
		}
		for _, e := range rep.NodeErrors {
			fmt.Printf("NODE DID NOT ANSWER: %s: %s\n", e.Node, e.Error)
		}
		if rep.Note != "" {
			fmt.Println("note:", rep.Note)
		}
		return
	}
	var out struct {
		Nodes      []FlowNodeStatus   `json:"nodes"`
		Exporters  []FlowExporterInfo `json:"exporters"`
		NodeErrors []NodeError        `json:"node_errors"`
	}
	decode(op(sock, "flow.status", nil), &out)
	for _, n := range out.Nodes {
		fmt.Printf("%s: %s; %d datagrams, %d records, %d bad, %d refused, %d without template, %d over the key limit; %d keys in %d minute and %d hourly buckets; %d templates\n",
			n.Node, map[bool]string{true: "collecting", false: "off"}[n.Enabled], n.Datagrams, n.Records, n.Bad, n.Refused, n.NoTemplate, n.Overflow, n.Keys, n.MinuteBkts, n.HourBkts, n.Templates)
		for _, l := range n.Listening {
			fmt.Println("    listening on", l)
		}
		fmt.Printf("    memory: about %s of a cap of %s; %d bucket(s) dropped by the cap\n", humanBytes(n.MemBytes), humanBytes(n.MemCap), n.MemDropped)
		if n.Dir != "" {
			fmt.Printf("    rollups kept in %s: %s of a cap of %s; %d file(s) removed by the cap\n", n.Dir, humanBytes(n.DirBytes), humanBytes(n.DirCap), n.CapRemoved)
		} else if n.DirError != "" {
			fmt.Println("    NO DISK: rollups are in memory only:", n.DirError)
		}
		for _, l := range n.Failed {
			fmt.Println("    CANNOT LISTEN on", l)
		}
	}
	for _, e := range out.NodeErrors {
		fmt.Printf("NODE DID NOT ANSWER: %s: %s\n", e.Node, e.Error)
	}
	if len(out.Exporters) > 0 {
		w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
		fmt.Fprintln(w, "EXPORTER\tNAME\tFORMAT\tNODE\tDATAGRAMS\tRECORDS\tLAST HEARD")
		for _, e := range out.Exporters {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%s ago\n", e.Addr, e.Name, e.Format, e.Node, e.Datagrams, e.Records, time.Since(time.Unix(e.Last, 0)).Round(time.Second))
		}
		w.Flush()
	}
}
