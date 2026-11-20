# Quick start

From nothing to a router's flows in front of an assistant, on one node.

## 1. Install

```
tar xzf flowdir_v38.tgz && cd flowdir
sudo ./install.sh --add-user "$USER"
```

## 2. Create the gateway

In the web GUI (`https://NODE:19996`, signed in as the user you added): Topology ▸ **＋ New gateway**. The gateway is one shared address (its VIP) that the exporters and the assistant use.

Or by hand:

```
sudo cp /usr/local/share/flowdir/flowdir.conf.example /var/lib/flowdir/flowdir.conf
sudo chmod 600 /var/lib/flowdir/flowdir.conf
sudo editor /var/lib/flowdir/flowdir.conf
```

Set:

- `groups[0].interface` and `vip4`: an unused address on that interface's subnet
- a long random `key`
- `settings.mcp_acl` to the address of the machine the assistant runs on

The daemon picks the file up by itself. Check:

```
flowdir --show-gateways
flowdir --canvas
```

## 3. List the exporters

Configure ▸ **Exporters** ▸ right-click ▸ Add row: a name, and the exporter's address, a network (`10.9.0.0/16`) or a host name. Flow packets are read only from listed exporters. The collector listens as soon as there is one.

Then point the router's NetFlow, IPFIX or sFlow export at the node's address or the gateway address: UDP 2055 (NetFlow), 4739 (IPFIX) or 6343 (sFlow). The **Flow** page (the first entry of the menu) shows the traffic within a minute or two.

## 4. Connect an assistant

Install a certificate the client trusts (`flowdir --tls-install --cert-file F --key-file F`), then, for Claude Code:

```
claude mcp add --transport http flowdir https://VIP/mcp
```

Ask it for `flow_top` by `service` over the last hour, or which exporters are sending.

## 5. More nodes

On a second node, install it the same way. Then run `flowdir --cluster-token` on the first node and `flowdir --cluster-join CODE` on the second (cluster port 19997). The gateway, the exporters and the access lists come across, and both nodes answer on the VIP.
