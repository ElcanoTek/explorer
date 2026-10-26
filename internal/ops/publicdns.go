// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package ops

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// publicResolver answers the bootstrap's DNS precheck. It is asked directly
// (DNS over TCP to a literal address) because the box's own resolver reads
// /etc/hosts, where a fresh Fedora box maps its FQDN to 127.0.0.1: that
// answer says nothing about what Let's Encrypt will see.
var publicResolver = "1.1.1.1:53"

// lookupPublic returns the A and AAAA addresses public DNS gives for host
// (a recursive resolver follows any CNAME chain and returns its records).
// A name that does not exist is no addresses and no error.
var lookupPublic = func(ctx context.Context, host string) (v4, v6 []netip.Addr, err error) {
	if v4, err = queryPublic(ctx, publicResolver, host, dnsmessage.TypeA); err != nil {
		return nil, nil, err
	}
	if v6, err = queryPublic(ctx, publicResolver, host, dnsmessage.TypeAAAA); err != nil {
		return nil, nil, err
	}
	return v4, v6, nil
}

// queryPublic sends one recursive query over TCP and returns the answer's
// addresses of the asked type.
func queryPublic(ctx context.Context, server, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	name, err := dnsmessage.NewName(strings.TrimSuffix(host, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("bad hostname %q: %w", host, err)
	}
	var idb [2]byte
	if _, err := rand.Read(idb[:]); err != nil {
		return nil, err
	}
	id := binary.BigEndian.Uint16(idb[:])
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{Name: name, Type: qtype, Class: dnsmessage.ClassINET}); err != nil {
		return nil, err
	}
	query, err := b.Finish()
	if err != nil {
		return nil, err
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if len(query) > 0xffff { // one question; never this long, but the frame length is 16 bits
		return nil, errors.New("DNS query too long")
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(query))) //nolint:gosec // bounded just above
	if _, err := conn.Write(append(frame, query...)); err != nil {
		return nil, err
	}
	var lenb [2]byte
	if _, err := io.ReadFull(conn, lenb[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(lenb[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}

	var p dnsmessage.Parser
	h, err := p.Start(reply)
	if err != nil {
		return nil, err
	}
	if h.ID != id || !h.Response {
		return nil, errors.New("DNS reply does not match the query")
	}
	if h.Truncated { // a partial answer could hide a wrong address
		return nil, errors.New("DNS reply was truncated")
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return nil, nil
	default:
		return nil, fmt.Errorf("DNS answered %s", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, err
	}
	var out []netip.Addr
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch {
		case rh.Type == dnsmessage.TypeA && qtype == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom4(r.A))
		case rh.Type == dnsmessage.TypeAAAA && qtype == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil, err
			}
			out = append(out, netip.AddrFrom16(r.AAAA))
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil, err
			}
		}
	}
	slices.SortFunc(out, func(a, b netip.Addr) int { return a.Compare(b) })
	return slices.Compact(out), nil
}

// strayAddrs returns the addresses in answers that are not one of the box's.
func strayAddrs(answers, box []netip.Addr) []string {
	var stray []string
	for _, a := range answers {
		if !slices.Contains(box, a) {
			stray = append(stray, a.String())
		}
	}
	return stray
}

func addrStrings(addrs []netip.Addr) string {
	s := make([]string, len(addrs))
	for i, a := range addrs {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}
