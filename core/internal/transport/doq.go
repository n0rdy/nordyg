package transport

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/n0rdy/nordyg/core/internal/contract"
)

func (c *Client) doq(ctx context.Context, ep contract.Endpoint, q *dns.Msg) (*Result, error) {
	hsStart := time.Now()
	conn, err := quic.DialAddr(ctx, ep.Address, &tls.Config{ServerName: ep.TLSName, RootCAs: c.RootCAs, NextProtos: []string{"doq"}, MinVersion: tls.VersionTLS13}, &quic.Config{})
	if err != nil {
		return nil, err
	}
	hs := time.Since(hsStart)
	defer func() { _ = conn.CloseWithError(0, "") }()

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = st.SetDeadline(time.Now()) })
	defer stop()
	// RFC 9250 §4.2.1: id must be 0; §4.2: two-byte length prefix.
	sendq := q.Copy()
	sendq.Id = 0
	packed, err := sendq.Pack()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 2+len(packed))
	binary.BigEndian.PutUint16(buf, uint16(len(packed)))
	copy(buf[2:], packed)
	if _, err := st.Write(buf); err != nil {
		return nil, err
	}
	if err := st.Close(); err != nil {
		return nil, err
	}
	var lenBuf [2]byte
	if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
		return nil, err
	}
	body := make([]byte, binary.BigEndian.Uint16(lenBuf[:]))
	if _, err := io.ReadFull(st, body); err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, malformed(err)
	}
	res := &Result{Msg: r, Size: len(body)}
	res.Exchange.Protocol = contract.DoQ
	res.Exchange.TLS = tlsInfo(conn.ConnectionState().TLS, hs)
	return res, nil
}
