package diag

import (
	"net"
	"testing"
)

func TestTraceDistinguishesHeaderFromReachedDestination(t *testing.T) {
	target := net.ParseIP("192.0.2.10")
	rows, replies, reached := traceRows([]byte("traceroute to example (192.0.2.10), 12 hops max\n1 *\n2 *\n"), []net.IP{target})
	if reached || replies != 0 || len(rows) != 2 {
		t.Fatal(rows, replies, reached)
	}
	rows, replies, reached = traceRows([]byte("1 192.168.1.1 2 ms\n2 192.0.2.10 8 ms\n"), []net.IP{target})
	if !reached || replies != 2 || rows[0] != "1 local-hop 2 ms" {
		t.Fatal(rows, replies, reached)
	}
}
