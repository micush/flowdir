# FlowDirector

FlowDirector (`flowdir`) is a clustered, highly available NetFlow, IPFIX and sFlow collector with a built-in [MCP](https://modelcontextprotocol.io) server. Routers, switches and firewalls send their flow exports to one address; an assistant such as Claude connects to the same address and asks what the biggest conversations, hosts, services and exporters of the last hour or week were. It is one Go program with no dependencies beyond the standard library.

What you get:

- **One address that survives a node failure.** Several nodes share a virtual IP (the gateway's **VIP**). The nodes elect a controller among themselves and spread clients across every node. A node can fail or restart without the exporters or the assistant losing the address.
- **Anycast over BGP or OSPF.** A gateway can also announce extra addresses to your routers through FRR, so every site exports to its nearest node. A node withdraws them when it cannot answer.
- **A flow collector.** NetFlow v5 and v9, IPFIX and sFlow v5, received on the gateway addresses, rolled up per node into one-minute and hourly totals, and reported across the whole cluster, with each flow counted once even when several exporters on its path report it.
- **Only listed exporters.** Flow packets carry no login, so flowdir accepts them only from the exporters you list: a name and an address, a network or a host name.
- **Read-only MCP, with guard rails.** Access is by address list or bearer key. The endpoint only reads: flow reports and the state of the cluster. Public addresses and AS numbers are hidden from the assistant by default (see [Privacy levels](#privacy-levels)), and every call is logged.
- **A cluster you manage from any node.** Shared settings, config history, certificates and software updates stay in step across the nodes, through a web GUI or the command line.

## Contents

- [Status](#status)
- [How it works](#how-it-works)
- [Install, upgrade, uninstall](#install-upgrade-uninstall)
- [Connecting an assistant](#connecting-an-assistant)
- [MCP tools](#mcp-tools)
- [Security](#security)
- [MCP usage](#mcp-usage)
- [Privacy levels](#privacy-levels)
- [Clustering](#clustering)
- [Anycast addresses, BGP and OSPF](#anycast-addresses-bgp-and-ospf)
- [Neighbor discovery (LLDP)](#neighbor-discovery-lldp)
- [Flow collector](#flow-collector)
- [Configuration file](#configuration-file)
- [Build from source](#build-from-source)
- [License](#license)

## Status

| Area | State |
|---|---|
| VIP election, anycast, BGP, OSPF, LLDP, cluster, users, backups, scheduler, updates | built in |
| Flow collector | NetFlow v5/v9, IPFIX and sFlow v5 received on the gateway addresses, rolled up per node, reported cluster-wide (`--flow-top`, MCP `flow_top`, `/api/flow/report`, **Flows** in the GUI; who is sending: **Monitor ▸ Exporters**); templates replicated between nodes |
| Exporters | **Configure ▸ Exporters** (`settings.flow.exporters`): a name and an address, a network or a host name; anything else is refused |
| MCP | read-only: `flow_top`, `flow_timeseries`, `flow_exporters`, `flow_status`, `list_nodes`, `get_topology` |
| Web GUI | Flow (the default page), Topology, Monitor, Configure |

## How it works

A **gateway** is one shared address, its VIP (IPv4, IPv6 or both), served by several nodes. The nodes of a gateway find each other over multicast, or over a unicast list where multicast is blocked, and elect one **controller (AGC)**. The others are **forwarders (AFN)**. The controller answers ARP and IPv6 neighbor solicitations for the VIP with the MAC address of a node chosen by the gateway's load-balancing method, so clients are spread over all the nodes. The MAC is either a virtual one per node, which another node takes over when that node fails, or, in real-MAC mode (the default for a new gateway), the node's own.

Every node that is active or forwarding answers on the VIP (and the other gateway addresses) with a listener of its own that serves only the MCP endpoint, `/mcp`, on port 443 by default (`settings.mcp_port`). The GUI does not answer on those addresses: it listens on port 19996 of the node's own addresses. A node whose MCP listener is not serving withdraws its anycast addresses, so traffic goes to a node that can answer.

One answer to an assistant is at most 1 MB by default and is cut, with a note, beyond that; `settings.mcp_max_result_mb` (Configure ▸ MCP ▸ Largest answer) raises it to at most 8. An assistant reads the answer into its context, and 1 MB of text is roughly 250,000 tokens, so ask for less before raising it.

## Install, upgrade, uninstall

Supported systems are Ubuntu, Debian, Fedora, RHEL, Rocky, Alma, Arch and Manjaro, and their derivatives. flowdir is Linux-only (macvlan, AF_PACKET, inotify).

```
tar xzf flowdir_v40.tgz && cd flowdir
sudo ./install.sh [--add-user NAME] [--no-start] [-y] [--dry-run]
sudo flowdir-uninstall [--purge]
```

The installer builds flowdir from the source tree with Go 1.24 or newer (it fetches a toolchain when the distribution's is too old). It installs only the missing prerequisites: gcc and the PAM headers, iproute2, FRR, nmap, ping and mtr, snmpd and lldpd. Then it sets up the `flowdir` group, the PAM service, the systemd unit and `/var/lib/flowdir`. Running it again on a newer tree upgrades. A start that fails rolls back to the previous binary.

`QUICKSTART.md` walks through a first gateway and connecting an assistant.

## Connecting an assistant

1. **Allow the caller.**
   - By address: add it to `settings.mcp_acl` (`"10.0.0.0/24"`). A privacy level may follow: `"10.0.0.0/24 strict"` (see [Privacy levels](#privacy-levels)). An entry may end in a note after a `#` (`"10.0.0.20 # mike's laptop"`, up to 200 characters, one line): it says what the entry is for and changes nothing.
   - An entry (or a key) can be switched off without deleting it: right-click ▸ **Disable**. In the file an address then ends with `disabled` and a key has `"disabled": true`; it allows nothing until enabled.
   - Or with a key that works from any address: Configure ▸ MCP ▸ Keys ▸ right-click ▸ **Add key** makes one and shows it once. In the file, `{"name": "laptop", "key": "<at least 32 random characters>"}` in `settings.mcp_keys` does the same. Only a SHA-256 hash of the key is kept. Both a key (`"expires": <unix time>`) and an address-list entry (`10.1.1.50 until=2026-12-31T17:00Z`) can have an expiry, in UTC; after it the key is refused as expired and the entry allows nothing, and the row stays in the list.
2. **Give the gateway a certificate the client trusts.** The GUI starts with a self-signed one; install yours with `flowdir --tls-install --cert-file F --key-file F`. The primary's certificate is copied to every node.
3. **Point the client at the VIP.** For Claude Code:

```
claude mcp add --transport http flowdir https://GATEWAY/mcp --header "Authorization: Bearer KEY"
```

The endpoint is MCP over streamable HTTP with JSON answers (protocol versions 2024-11-05 to 2025-11-25). Requests from a browser page on another origin are refused.

## MCP tools

| Tool | What it does |
|---|---|
| `flow_top` | the biggest conversations, hosts, sources, destinations, services, protocols, flows, exporters, interfaces or AS numbers of a time range, with filters such as `exporter=sw1 AND port=443`; bytes, packets or flows, shares and average rates |
| `flow_timeseries` | the same over time, in steps, for a chart |
| `flow_exporters` | the exporters that are sending (and when each was last heard from), and what was refused |
| `flow_status` | the collector on every node: what it listens on, counters, caps |
| `list_nodes`, `get_topology` | the cluster status: the nodes (reachable, paused, primary, version, update state) and the gateways with their active node and anycast addresses |
| *(nothing else)* | **An MCP caller can only read flows and the state of the cluster.** There is no tool for flowdir's own configuration, the GUI's API, alerts, the scheduler, updates, the host's load, LLDP, the log, users, backups or cluster tokens, and no tool takes a `node`: the node that serves the endpoint answers, and a `node` argument is refused. Those are read in the GUI or the CLI by an administrator. |

## Security

- **MCP reads, never writes.** Nothing can be changed over MCP: settings, the cluster, gateways, schedules, updates, alerts, users and certificates are changed in the GUI. The rule is in the request path, so no route is missed.
- **Secrets never reach a caller.** Keys, SNMP communities, passwords and join codes read `(hidden)` to every MCP caller. A read-only GUI account sees `(hidden)` too.
- **Flow packets are not authenticated.** UDP exports carry no login, so only the exporters you list are read (Configure ▸ Exporters); any other sender is dropped before a byte is decoded and counted as refused. List only addresses that cannot be spoofed from outside your network.
- **Everything is logged.** Each MCP call is logged with the caller's name (`KEYNAME@ADDRESS` or the address) and the tool.
- **Treat answers as data.** Whatever an answer holds (host names, exporter names) is data for the assistant, never instructions. The MCP server says so in its instructions to the client.
- **Where credentials live.** They are kept in the configuration file (`/var/lib/flowdir/flowdir.conf`, mode 0600, root) and replicated to the cluster's nodes over the pinned, signed cluster channel.

## MCP usage

**Monitor ▸ MCP** shows what the MCP endpoint is used for on the node the Node menu has picked: calls by **key** (or *(address list)* for a caller let in by its address), by **source address** and by **tool**, with errors, refused calls, the data returned and the average time; a chart of calls per hour; and the newest 200 calls. The page is laid out like Monitor ▸ Node (time range buttons, tiles, charts per hour, tables), sits just below it in the menu, and its time range is the last hour, day or week. The daemon keeps the counts by the hour for 8 days (`mcpusage.json` in the state directory, so they survive a restart and an upgrade); the newest-calls list lives in memory. Only names, sizes and times are kept, never what a caller sent or was answered. The same numbers are `GET /api/mcpusage?window=24h`. Each node counts the calls it answers, so pick each node in turn to see a whole cluster.

## Privacy levels

What an assistant is told can be limited, because the assistant is usually a public AI service. Every answer is rewritten on its way out: a hidden address becomes `x.x.x.x` (or shows some of its parts), a hidden AS number shows its last three digits, an e-mail address shows only the name before the `@`, and a serial number or word of yours becomes a token that is the same for the same value. The tokens change when the daemon restarts and cannot be turned back into the value. Three levels:

| Level | Hides |
|---|---|
| `none` | nothing: every address and AS number is shown as it is. flowdir's own keys and tokens stay hidden. Every such answer is logged. |
| `standard` (default) | public IP addresses and AS numbers, e-mail addresses, SNMP contact and location, serial numbers except the last four characters |
| `strict` | all of that, private IP addresses and AS numbers, MAC addresses, serial numbers completely |

Configure ▸ Privacy sets the **default** level, for callers that have none of their own, and what each of `standard` and `strict` hides: public and private addresses, AS numbers, e-mail addresses, contacts, serial numbers (shown, last four, hidden), MAC addresses (shown, vendor part, last three bytes, hidden), how many leading or trailing digits of a hidden address stay readable (`203.0.x.x`, or `x.x.114.7`), and a list of your own words (company, site and host names) that are always hidden. A key has a **Privacy** setting in Configure ▸ MCP ▸ Keys and an allowed source has one in the same table. A caller with both a key and an address gets the strictest.

In the file:

```json
"settings": {
  "mcp_acl": ["10.0.0.20 strict # mike's laptop", "10.0.0.0/24 none"],
  "mcp_keys": [{"name": "laptop", "access": "ro", "privacy": "strict", "notes": "for the audit", "key": "…"}],
  "privacy": {"default": "standard", "strict": {"public_ips": true, "private_ips": true, "ip_keep": -2,
    "public_asns": true, "private_asns": true, "serials": "hide", "macs": "nic", "emails": true,
    "contacts": true, "words": ["contoso", "lab-edge"]}}
}
```

Hiding is best effort: a value written in an unusual way, an address split over two fields or a host name is not recognised. With no `privacy` setting the standard level applies.

## Clustering

Several nodes are managed as one cluster. The cluster is for management and is independent of the gateway election.

- **Roles.** One node is the primary and the others are replicas.
- **Shared and per-node settings.** The `settings` block, the gateways' VIPs, keys and timers, the web login groups and the sign-in rules are shared. They can be edited on any node and are applied on the primary. Interface, priority, weight and the web and cluster blocks stay per node.
- **Joining.** Create a join code on a member (`--cluster-token`) and use it on the new node (`--cluster-join CODE`). A code works once, for an hour. A node keeps at most 20 unused codes; `--cluster-token-clear` (Operate ▸ Cluster ▸ **Clear join codes**) withdraws them.
- **Trust.** Nodes pin each other's certificates and sign every request.
- **Promotion and failover.** Promotion is explicit (`--cluster-promote`). With three or more members there is also automatic failover after 5 minutes, and the primary role is handed over before a planned restart. For an update the hand-over is temporary: the node that was primary when the update began is remembered (by whichever node holds the role, as it passes from node to node), and once nothing is queued, installing or restarting any more (30 seconds in a row) the role goes back to it. A node whose update failed, a member that was removed, or a promotion by hand (or by failover) drops it; a plain restart or shutdown leaves the role where it landed.
- **Updates.** Upload a release archive on any node (`--update-upload`). Each node then builds it, swaps its binary and restarts, one node at a time, with automatic rollback.

## Anycast addresses, BGP and OSPF

A gateway's anycast addresses (`extra_vips`) are held on `lo` of every node that runs the gateway, with a 10 s lifetime renewed every 3 s. FRR announces them over BGP (with BFD) or OSPF. An address is withdrawn when:

- the node's listener is not serving,
- the gateway is paused or stops,
- no BGP neighbor of its family is established (and OSPF is not carrying it), or
- flowdir stops.

A `kill -9` takes it away within the lifetime. BGP and OSPF settings are per node: `--asn`, `--bgp-neighbor-add`, `--ospf-interface-add`; see `flowdir --help`.

## Neighbor discovery (LLDP)

With `settings.lldp` on, every node runs lldpd. The switches then see the nodes, and each node reports the switch port it is on (`flowdir --lldp` and the GUI). This is reporting only.

## Flow collector

The cluster is also a flow collector. Point a router's NetFlow v5/v9, IPFIX or sFlow v5 export at a **gateway address** (a VIP, a further address or an anycast address) and whichever node answers for it receives the flows. When the VIP moves or the anycast path changes, the exporter's packets reach another node and nothing is reconfigured on the router.

```
"settings": { "flow": { "exporters": [                                         // shared
    {"name": "core-sw1", "address": "10.9.0.1"},
    {"name": "branches", "address": "10.20.0.0/16"},
    {"name": "fw1", "address": "fw1.example.com"} ],
  "dir_max_percent": 90, "mem_max_percent": 90 } }                              // shared: disk and memory caps
"flow_listen": ["10.0.0.5"]                                                    // this node only: listen only on these (and the gateway addresses)
"flow_dir": "/data/flow"                                                       // this node only: where the rollups are kept
```

| Setting | Meaning |
|---|---|
| `enabled` | listen on UDP 2055 (NetFlow), 4739 (IPFIX) and 6343 (sFlow) on every address of this node (so an exporter can send to the node itself or to a gateway address); implied as soon as there is an exporter |
| `netflow_port`, `ipfix_port`, `sflow_port` | another port; `-1` turns that listener off |
| `exporters` (Configure ▸ Exporters) | the senders accepted: a `name` and an `address` (an IPv4 or IPv6 address, a network such as `10.9.0.0/16`, or a host name looked up every minute), and `disabled` to keep an entry without accepting it. A network's name stands for every address in it. Anything else is counted as refused and dropped |
| `dedupe` (Configure ▸ Settings ▸ General ▸ Flow) | on unless `false`: a flow that several exporters report (a path of switches, a switch and a firewall) is counted once in reports. A report can ask either way with `dedupe=on` or `dedupe=off` |
| `max_keys` | keys per minute bucket (default 100000); more are folded into one "other" entry per exporter and counted |
| `minute_hours`, `hour_days`, `hour_top_keys` | minute buckets kept 6 h; hourly buckets kept until the disk cap removes the oldest file (`hour_days` sets a limit in days if you want one), each keeping its 20000 biggest keys. A report can go back as far as that: the GUI has 30 Days, 90 Days and All, the API `range=30d`, `90d`, `1y` or `all`. Each hour held costs memory (about 220 bytes a key, so up to 4.4 MB at 20000 keys), and `mem_max_percent` drops the oldest hours when it is reached |
| `flow_listen` (per node) | when set, listen only on these local addresses and on the gateway addresses this node serves, instead of on every address; `0.0.0.0` takes every address |
| `flow_dir` (per node; Configure ▸ Settings ▸ General ▸ Flow ▸ Storage folder) | the folder the rollups are written to (default `flow/` in the state directory); an absolute path, created if missing |
| `dir_max_percent` (Configure ▸ Settings ▸ General ▸ Flow) | cap on the folder: this percent (default 90) of the volume it is on. At the cap the oldest files are deleted first (FIFO), never the one being written |
| `mem_max_percent` (Configure ▸ Settings ▸ General ▸ Flow) | cap on what the rollups hold in memory: this percent (default 90) of the machine's memory, or of the cgroup limit when that is smaller. At the cap the oldest buckets are dropped first (FIFO), never the newest minute; the files of dropped hours stay on disk, and a report that reaches back to them reads them from there (slower the first time: a report over 20 GB of history is limited by the disk; what it learns about each hour, and for the common groupings the hour's sums, is kept in memory so the next report is fast) |

**What is stored.** Rollups, not raw flows: per minute, bytes, packets and flows by exporter, source, destination, service port, protocol, the two interfaces and the two AS numbers. The client's ephemeral port is dropped, so the number of keys follows the number of conversations. A flow is filed under the time it ended. Sampling (the NetFlow v5 header, a v9/IPFIX options record, the sFlow sample) is applied: the numbers are estimates of the real traffic. Rollups are written to `flow/` in the state directory and read back at start.

**In the GUI** (Flow, the first entry of the menu, above Topology): a stacked chart of the biggest talkers over time, a ranked list under it, and the exporters that are sending. Pick a time range (15 minutes to 7 days), what to group by and what to measure; click an address, service, protocol, exporter or interface to look at just that (the page moves one level down: after a host, its conversations), or write a filter in the box. A filter has terms `name=value` (`exporter`, `host`, `src`, `dst`, `port`, `proto`, `interface`, `as`; commas make alternatives; a bare number means `port=`, any other bare word `host=`) joined by `AND` and `OR`, negated with `!` or `NOT`, and grouped with brackets: `(src=10.1.0.0/16 OR dst=10.1.0.0/16) AND port=443 AND !host=10.1.1.1`. `AND` binds tighter than `OR`, and terms side by side are `AND`. The same filter is the `filter` argument of `--flow-top`, `/api/flow/report` and the MCP tools; while one is set, the traffic the rollups folded into "everything smaller" is left out, because it has no addresses to test. The page calls `/api/flow/report`, so it shows the whole cluster whichever node you are signed in to. **Topology** draws each gateway with the exporters that are sending to it: a square for each exporter heard in the last 15 minutes (titled with the host part of its reverse-DNS name, else its Exporters entry name, else its address) whose datagrams came in on one of the gateway's addresses (the VIP or an anycast address; the collector asks the kernel for the address each datagram arrived on, so `/api/flow/exporters` lists it as `to`), green while its last datagram is under 5 minutes old, amber from 5 to 10 minutes, red from 10 to 15, then gone; not heard, not drawn. Above `settings.topology_squares_above` exporters (default 36, Configure ▸ Settings ▸ General ▸ Topology) they are small squares, and the filter box at the top left (`AND`, `OR`, `!`) keeps the ones that match, full size. A click opens Flow on that exporter. Wildcards work in `host`, `src`, `dst` and in bare words: `10.1.1.*` is the subnet 10.1.1.0/24, `10.1.*.*` is 10.1.0.0/16, `*.cox.net` is every host whose DNS name ends in .cox.net, `2001:db8:*` every address that starts that way. A filter that is not understood turns the box red (the reason is its tooltip); nothing is written beside it.

**One flow, several exporters.** If four switches on a path all export the same flow, flowdir stores four entries (the exporter is part of the key), but reports count it once by default: for each flow (the two addresses, the service port and the protocol), over the range of the report, the exporter that counted the most bytes is the one that counts, and the others are left out. This is the right answer when each exporter sees the whole flow. It is not a sum of what different exporters saw of different flows, so a flow seen by only one exporter still counts. It works across the cluster, so exporters whose packets land on different nodes (anycast) are weighed against each other: the node you ask first collects a digest of every node's flows (flow, exporter, bytes), decides which reports to leave out, and sends that with the query. An exporter whose packets moved from one node to another counts as one exporter. Limits: each node sends the biggest 100000 flows of the range to the digest, so smaller flows seen by exporters on different nodes can still count twice (the answer says `dedupe_cut`); the choice is made over the whole range, not minute by minute; a flow whose addresses are translated on the path (NAT) has two different keys and counts twice; and a report costs one more round trip to the other nodes. Reports grouped by `exporter` or `interface` are never deduplicated: they show what each device saw. `dedupe=off` (or `"dedupe": false` in `settings.flow`) adds every exporter's report; the answer says `deduplicated` when the setting applied.

**Caps.** Both caps are checked once a minute. The folder cap counts only the files flowdir writes there (`m-*.gob`, `h-*.gob`; they are compressed, see below). The memory figure is an estimate (about 220 bytes a key plus a little per bucket), not a measurement. At start, history is read back newest first and reading stops at the memory cap; the older hourly files stay on disk and reports read them when asked. Reports over a day or more that group by host, source, destination, conversation or flow use each hour's 1,000 biggest groups by bytes and by packets (the answer is marked approximate; totals are exact); the cache that holds them is not part of the memory figure and is at most 2% of the machine's memory. flowdir has no other memory limit, so `mem_max_percent` is the only one. Every removal is logged, and `flowdir --flow` shows both caps and how much each has removed.

**Compression.** Each minute and hour is written as a frame, encoded and packed by a writer goroutine that holds no store lock, packed with a small LZ4-style codec built into flowdir (no library, no setting). On test data it saves about 40% of the disk space for about 5 ms of CPU per minute at 20,000 keys. Every frame carries a checksum; a frame cut short by a kill or damaged on disk ends that file and the records before it are kept. Files written by an older version (plain, not compressed) are still read, and are replaced as they age out. Nothing needs converting.

**In the cluster.** Every flow is stored on the node that received it, and on no other, so a cluster-wide report is the sum of the nodes' reports with nothing counted twice. The node you ask fans the question out over the signed cluster channel, adds the answers and cuts the list; a node that does not answer is named in the report, and its flows are missing from the totals. Templates and sampling rates (NetFlow v9, IPFIX) are copied to the other nodes as soon as one learns them, and a node that starts fetches everything the others know: an exporter whose packets move to another node is read at once instead of after its next template refresh. A node's history is not copied to another node: if it is lost, its flows are unavailable until it returns.

**Reports** (the same everywhere: `--flow-top`, the MCP tools `flow_top`, `flow_timeseries`, `flow_exporters`, `flow_status`, and `GET /api/flow/report`, `/api/flow/exporters`, `/api/flow/status`):

```
flowdir --flow                                              the collector on every node, and the exporters
flowdir --flow-top conversation --flow-args "range=1h"
flowdir --flow-top service      --flow-args "range=1d&exporter=fw1&host=10.1.0.0/16"
flowdir --flow-top interface    --flow-args "range=15m&exporter=core1&metric=packets"
```

`by` is `conversation`, `flow`, `src`, `dst`, `host` (a host in either role), `service`, `protocol`, `exporter`, `interface` (by ifIndex, in and out), `src_as` or `dst_as`. Filters: `exporter` (a name from Configure ▸ Exporters, an address or a network), `host`, `src`, `dst` (addresses, networks or names), `port` (a number or `https`, `dns`, ...), `proto`, `interface`, `as`. A range is `15m`, `1h`, `1d`, `7d`, `30d`, or `from` and `to`. Rows carry bytes, packets, flows, the share of what matched, the average rate, and names where known (the exporter's name, a host's DNS name, a service). Ranges of hours or more use the hourly rollups, which keep only the biggest keys; the answer says when that changes the numbers. MCP callers see addresses as their privacy level allows (Configure ▸ Privacy).

**Limits.** NetFlow v5, v9, IPFIX and sFlow v5 raw-packet-header samples only; no IPFIX enterprise fields, no MPLS, no flow start times (a long flow is counted in the minute it ended). UDP source addresses are not authenticated: the exporter list is an address list, not a credential.

## DNS registration

Each node can put its own addresses into DNS, so its name follows the address it has (Configure ▸ Settings ▸ DNS, or `--dnsreg`). It uses RFC 2136 dynamic updates over TCP, signed with a TSIG key (hmac-md5, -sha1, -sha256, -sha384 or -sha512):

- `host.domain`: the node's first IPv4 address (A) and first IPv6 address (AAAA).
- `host-interface.domain`: every address of that interface.
- A PTR record for each address, in its reverse zone (a /24 for IPv4, a /64 for IPv6), pointing at the first of its names.

The domain is the first search domain in `/etc/resolv.conf` and the server is the primary named by the zone's SOA record, unless the `domain` and `server` settings say otherwise. A check runs every `interval_sec` (default 300, plus up to 30 % at random) and sends an update only for a record that is wrong or missing. Loopback, link-local and multicast addresses, interfaces that are down, interfaces matching `skip_interfaces`, and the gateways' own VIPs and anycast addresses are never registered. The setting is per node and never replicated (`dns_register` in the node's config file; the `key` is hidden from read-only accounts and from the troubleshooting bundle).

```
flowdir --dnsreg-key ddns-key:c2VjcmV0c2VjcmV0 --dnsreg-enable
flowdir --dnsreg-now        # check now and list every record
flowdir --dnsreg-remove     # take this node's records out (turn registration off first)
```

## Configuration file

`/var/lib/flowdir/flowdir.conf` (JSON, mode 0600). Changes apply live: the daemon watches the file. `source/flowdir.conf.example` is a starting point, and `flowdir --help` lists every key. The top-level blocks are:

- `groups`: the gateways
- `settings`: shared by the cluster
- `web`: the GUI and MCP listener
- `cluster`, `bgp`, `ospf`, `snmp`, `syslog`, `dns_register`, `log_level`

Every change from any source is kept as a version in `/var/lib/flowdir/versions`: `--versions`, `--version-diff`, `--version-restore`.

## Build from source

From `source/`:

```
go build -o flowdir .
go test ./...                # Linux only
```

flowdir uses Go's standard library only. The GUI's PAM login needs cgo and the PAM headers. A build without cgo serves no GUI, and with it no MCP endpoint.

## License

GPL-3.0; see `LICENSE`.

