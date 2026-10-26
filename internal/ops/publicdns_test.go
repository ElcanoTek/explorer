package ops

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// fakeDNS serves DNS over TCP on 127.0.0.1 with answer(question) -> (rcode,
// resources). It replies with the query's own id unless wrongID is set.
func fakeDNS(t *testing.T, wrongID bool, answer func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource)) string {
	return fakeDNSWith(t, wrongID, false, answer)
}

func fakeDNSWith(t *testing.T, wrongID, truncated bool, answer func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var lenb [2]byte
				if _, err := io.ReadFull(c, lenb[:]); err != nil {
					return
				}
				buf := make([]byte, binary.BigEndian.Uint16(lenb[:]))
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				var msg dnsmessage.Message
				if err := msg.Unpack(buf); err != nil {
					return
				}
				rcode, res := answer(msg.Questions[0])
				id := msg.ID
				if wrongID {
					id++
				}
				reply := dnsmessage.Message{
					Header:    dnsmessage.Header{ID: id, Response: true, RecursionAvailable: true, RCode: rcode, Truncated: truncated},
					Questions: msg.Questions,
					Answers:   res,
				}
				out, err := reply.Pack()
				if err != nil {
					return
				}
				_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(out))), out...))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func rrA(name string, ip string) dnsmessage.Resource {
	a := netip.MustParseAddr(ip).As4()
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.AResource{A: a},
	}
}

func rrCNAME(name, target string) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName(target)},
	}
}

func TestQueryPublicReadsTheAnswerAndFollowsTheChain(t *testing.T) {
	server := fakeDNS(t, false, func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		if q.Type != dnsmessage.TypeA {
			return dnsmessage.RCodeSuccess, nil
		}
		return dnsmessage.RCodeSuccess, []dnsmessage.Resource{
			rrCNAME("explorer.acmevic.com.", "edge.acmevic.com."),
			rrA("edge.acmevic.com.", "203.0.113.9"),
			rrA("edge.acmevic.com.", "203.0.113.7"),
		}
	})
	got, err := queryPublic(context.Background(), server, "explorer.acmevic.com", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if addrStrings(got) != "203.0.113.7, 203.0.113.9" {
		t.Fatalf("got %v", got)
	}
}

func TestQueryPublicTreatsNXDOMAINAsNoAddressesAndOtherErrorsAsErrors(t *testing.T) {
	nx := fakeDNS(t, false, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		return dnsmessage.RCodeNameError, nil
	})
	if got, err := queryPublic(context.Background(), nx, "nope.acmevic.com", dnsmessage.TypeA); err != nil || len(got) != 0 {
		t.Fatalf("NXDOMAIN: got %v, %v", got, err)
	}
	fail := fakeDNS(t, false, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		return dnsmessage.RCodeServerFailure, nil
	})
	if _, err := queryPublic(context.Background(), fail, "x.acmevic.com", dnsmessage.TypeA); err == nil {
		t.Fatal("SERVFAIL must be an error, never 'no addresses'")
	}
	spoof := fakeDNS(t, true, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		return dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("x.acmevic.com.", "198.51.100.1")}
	})
	if _, err := queryPublic(context.Background(), spoof, "x.acmevic.com", dnsmessage.TypeA); err == nil {
		t.Fatal("a reply with another id must be refused")
	}
}

func TestQueryPublicRefusesATruncatedReply(t *testing.T) {
	server := fakeDNSWith(t, false, true, func(dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		return dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("x.acmevic.com.", "140.82.8.11")}
	})
	if _, err := queryPublic(context.Background(), server, "x.acmevic.com", dnsmessage.TypeA); err == nil {
		t.Fatal("a truncated reply may omit a wrong address; it must be an error")
	}
}

func TestQueryPublicDecodesAAAAAnswers(t *testing.T) {
	server := fakeDNS(t, false, func(q dnsmessage.Question) (dnsmessage.RCode, []dnsmessage.Resource) {
		if q.Type != dnsmessage.TypeAAAA {
			return dnsmessage.RCodeSuccess, []dnsmessage.Resource{rrA("x.acmevic.com.", "140.82.8.11")}
		}
		return dnsmessage.RCodeSuccess, []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("x.acmevic.com."), Type: dnsmessage.TypeAAAA,
				Class: dnsmessage.ClassINET},
			Body: &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::7").As16()},
		}}
	})
	got, err := queryPublic(context.Background(), server, "x.acmevic.com", dnsmessage.TypeAAAA)
	if err != nil || addrStrings(got) != "2001:db8::7" {
		t.Fatalf("got %v, %v", got, err)
	}
}

func TestThePublicResolverIsAnAddressNotAName(t *testing.T) {
	// Asked by address, so neither /etc/hosts nor the box's resolver is involved.
	if _, err := netip.ParseAddrPort(publicResolver); err != nil {
		t.Fatalf("publicResolver %q must be an ip:port literal: %v", publicResolver, err)
	}
}

func withDNS(t *testing.T, v4, v6 []string, err error, box4, box6 []string) {
	t.Helper()
	parse := func(ss []string) []netip.Addr {
		out := make([]netip.Addr, 0, len(ss))
		for _, s := range ss {
			out = append(out, netip.MustParseAddr(s))
		}
		return out
	}
	oldLookup, oldBox := lookupPublic, boxPublicAddrs
	t.Cleanup(func() { lookupPublic, boxPublicAddrs = oldLookup, oldBox })
	lookupPublic = func(context.Context, string) ([]netip.Addr, []netip.Addr, error) {
		return parse(v4), parse(v6), err
	}
	boxPublicAddrs = func(context.Context) ([]netip.Addr, []netip.Addr) { return parse(box4), parse(box6) }
}

func TestDNSPrecheck(t *testing.T) {
	box := []string{"140.82.8.11"}
	cases := []struct {
		name          string
		v4, v6        []string
		err           error
		box4, box6    []string
		want, notWant string
	}{
		{"points here (the /etc/hosts loopback case no longer matters)", []string{"140.82.8.11"}, nil, nil, box, nil,
			"DNS resolves correctly (140.82.8.11)", "mismatch"},
		{"one right and one stale A", []string{"140.82.8.11", "198.51.100.9"}, nil, nil, box, nil,
			"DNS mismatch: explorer.acmevic.com → 140.82.8.11, 198.51.100.9, this box → 140.82.8.11", "resolves correctly"},
		{"AAAA but no IPv6 here", []string{"140.82.8.11"}, []string{"2001:db8::1"}, nil, box, nil,
			"has AAAA 2001:db8::1 but this box has no public IPv6", "resolves correctly"},
		{"AAAA that is this box", []string{"140.82.8.11"}, []string{"2001:db8::1"}, nil, box, []string{"2001:db8::1"},
			"DNS resolves correctly (140.82.8.11, 2001:db8::1)", "mismatch"},
		{"not in DNS yet", nil, nil, nil, box, nil, "doesn't resolve in public DNS yet", "resolves correctly"},
		{"lookup failed", nil, nil, errors.New("i/o timeout"), box, nil, "could not check public DNS", "resolves correctly"},
		{"own address unknown", []string{"140.82.8.11"}, nil, nil, nil, nil, "could not learn this box's public IPv4",
			"resolves correctly"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			withDNS(t, c.v4, c.v6, c.err, c.box4, c.box6)
			u, buf := testUI()
			dnsPrecheck(context.Background(), u, "explorer.acmevic.com")
			out := buf.String()
			if !strings.Contains(out, c.want) {
				t.Fatalf("want %q in:\n%s", c.want, out)
			}
			if strings.Contains(out, c.notWant) {
				t.Fatalf("did not want %q in:\n%s", c.notWant, out)
			}
		})
	}
}
