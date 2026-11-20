package main

import (
	"net/netip"
	"syscall"
)

// flowListenControl is freebindControlUDP, and asks the kernel to say which local address each datagram came in on: a socket bound to
// the wildcard address serves every gateway's address, and the Topology page draws an exporter on the gateway it sends to.
func flowListenControl(network, address string, c syscall.RawConn) error {
	if err := freebindControlUDP(network, address, c); err != nil {
		return err
	}
	c.Control(func(fd uintptr) { // best effort: without it the exporter is just not tied to a gateway
		if network == "udp6" {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_RECVPKTINFO, 1)
		} else {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_PKTINFO, 1)
		}
	})
	return nil
}

// pktinfoDst is the destination address in the control messages that came with a datagram (invalid when there is none).
func pktinfoDst(oob []byte) netip.Addr {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return netip.Addr{}
	}
	for _, m := range msgs {
		switch {
		case m.Header.Level == syscall.IPPROTO_IP && m.Header.Type == syscall.IP_PKTINFO && len(m.Data) >= 12:
			// struct in_pktinfo: ifindex (4), the address the route chose (4), the address in the packet header (4)
			return netip.AddrFrom4([4]byte(m.Data[8:12]))
		case m.Header.Level == syscall.IPPROTO_IPV6 && m.Header.Type == syscall.IPV6_PKTINFO && len(m.Data) >= 16:
			// struct in6_pktinfo: the address in the packet header (16), ifindex (4)
			a := netip.AddrFrom16([16]byte(m.Data[0:16]))
			return a.Unmap()
		}
	}
	return netip.Addr{}
}
