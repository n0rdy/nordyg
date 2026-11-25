// Package transport sends one DNS message to one endpoint over udp, tcp, dot,
// doh or doq and reports what happened on the wire.
package transport

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

// Client performs exchanges. The zero value uses the system trust store.
type Client struct {
	// RootCAs overrides certificate verification roots. Tests only.
	RootCAs *x509.CertPool
}

// Result is a completed exchange.
type Result struct {
	Msg      *dns.Msg
	Size     int
	Exchange contract.Exchange
}

const maxMessage = 65535

// Exchange sends q to ep. The message is not modified; a copy is sent. The
// options supply the timeout and the UDP-to-TCP fallback policy. bootstrap
// is consulted only for doh endpoints without a pinned address.
func (c *Client) Exchange(ctx context.Context, ep contract.Endpoint, q *dns.Msg, o contract.Effective, bootstrap []contract.Endpoint) (*Result, error) {
	if err := ep.Validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()

	start := time.Now()
	var (
		res *Result
		err error
	)
	switch ep.Transport {
	case contract.UDP:
		res, err = c.udp(ctx, ep, q, o)
	case contract.TCP:
		res, err = c.tcp(ctx, ep, q)
	case contract.DoT:
		res, err = c.dot(ctx, ep, q)
	case contract.DoH:
		res, err = c.doh(ctx, ep, q, o, bootstrap)
	case contract.DoQ:
		res, err = c.doq(ctx, ep, q)
	}
	if err != nil {
		return nil, classify(ctx, err)
	}
	res.Exchange.Endpoint = ep
	res.Exchange.StartedAt = start.UTC()
	res.Exchange.RTTms = ms(time.Since(start))
	return res, nil
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func (c *Client) udp(ctx context.Context, ep contract.Endpoint, q *dns.Msg, o contract.Effective) (*Result, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", ep.Address)
	if err != nil {
		return nil, err
	}
	// o.UDPSize is what the query advertises in EDNS. Some resolvers ignore it
	// and send larger datagrams; reading into a buffer of the advertised size
	// would cut those off mid-record, so always read up to the maximum.
	co := &dns.Conn{Conn: conn, UDPSize: dns.MaxMsgSize}
	res, err := exchangeConn(ctx, co, q)
	_ = conn.Close()
	if err != nil {
		return nil, err
	}
	res.Exchange.Protocol = contract.UDP
	if res.Msg.Truncated && o.TCPFallback {
		tcpRes, err := c.tcp(ctx, ep, q)
		if err != nil {
			return nil, err
		}
		tcpRes.Exchange.TruncatedRetry = true
		return tcpRes, nil
	}
	return res, nil
}

func (c *Client) tcp(ctx context.Context, ep contract.Endpoint, q *dns.Msg) (*Result, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	res, err := exchangeConn(ctx, &dns.Conn{Conn: conn}, q)
	if err != nil {
		return nil, err
	}
	res.Exchange.Protocol = contract.TCP
	return res, nil
}

func (c *Client) dot(ctx context.Context, ep contract.Endpoint, q *dns.Msg) (*Result, error) {
	d := &net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", ep.Address)
	if err != nil {
		return nil, err
	}
	tconn := tls.Client(raw, &tls.Config{ServerName: ep.TLSName, RootCAs: c.RootCAs, NextProtos: []string{"dot"}, MinVersion: tls.VersionTLS12})
	hsStart := time.Now()
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	hs := time.Since(hsStart)
	defer func() { _ = tconn.Close() }()
	res, err := exchangeConn(ctx, &dns.Conn{Conn: tconn}, q)
	if err != nil {
		return nil, err
	}
	res.Exchange.Protocol = contract.DoT
	res.Exchange.TLS = tlsInfo(tconn.ConnectionState(), hs)
	return res, nil
}

// exchangeConn writes q and reads the matching reply on an established
// connection. Cancellation is wired to the deadline so a hung read aborts.
func exchangeConn(ctx context.Context, co *dns.Conn, q *dns.Msg) (*Result, error) {
	if dl, ok := ctx.Deadline(); ok {
		_ = co.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = co.SetDeadline(time.Now()) })
	defer stop()

	if err := co.WriteMsg(q); err != nil {
		return nil, err
	}
	for {
		p, err := co.ReadMsgHeader(nil)
		if err != nil {
			return nil, err
		}
		r := new(dns.Msg)
		if err := r.Unpack(p); err != nil {
			return nil, malformed(err)
		}
		if r.Id != q.Id {
			// Stray or spoofed datagram on UDP; keep waiting for ours.
			continue
		}
		return &Result{Msg: r, Size: len(p)}, nil
	}
}

func tlsInfo(cs tls.ConnectionState, handshake time.Duration) *contract.TLSInfo {
	info := &contract.TLSInfo{
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
		ServerName:  cs.ServerName,
		ALPN:        cs.NegotiatedProtocol,
		HandshakeMS: ms(handshake),
	}
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		sum := sha256.Sum256(leaf.Raw)
		info.Certificate = &contract.Certificate{
			Subject:   leaf.Subject.String(),
			Issuer:    leaf.Issuer.String(),
			DNSNames:  leaf.DNSNames,
			NotBefore: leaf.NotBefore.UTC(),
			NotAfter:  leaf.NotAfter.UTC(),
			SHA256:    hex.EncodeToString(sum[:]),
		}
		if info.Certificate.DNSNames == nil {
			info.Certificate.DNSNames = []string{}
		}
	}
	return info
}

func malformed(err error) error {
	return &bridge.Error{Code: contract.CodeMalformed, Message: "response did not parse: " + err.Error()}
}

// classify maps Go errors to contract error codes. Errors that are already
// *bridge.Error pass through; cancellation is reported as context.Canceled so
// the bridge turns it into the cancelled code.
func classify(ctx context.Context, err error) error {
	var be *bridge.Error
	if errors.As(err, &be) {
		return be
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if isTLS(err) {
		return &bridge.Error{Code: contract.CodeTLS, Message: err.Error()}
	}
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return &bridge.Error{Code: contract.CodeTimeout, Message: err.Error()}
	}
	return &bridge.Error{Code: contract.CodeNetwork, Message: err.Error()}
}

func isTLS(err error) bool {
	var (
		cv  *tls.CertificateVerificationError
		ua  x509.UnknownAuthorityError
		hn  x509.HostnameError
		ci  x509.CertificateInvalidError
		rh  tls.RecordHeaderError
		al  tls.AlertError
		te  *quic.TransportError
		ecv *tls.ECHRejectionError
	)
	switch {
	case errors.As(err, &cv), errors.As(err, &ua), errors.As(err, &hn), errors.As(err, &ci), errors.As(err, &rh), errors.As(err, &al), errors.As(err, &ecv):
		return true
	case errors.As(err, &te) && te.ErrorCode.IsCryptoError():
		return true
	}
	// net/http wraps TLS failures in *url.Error with the text intact.
	s := err.Error()
	return strings.Contains(s, "tls:") || strings.Contains(s, "x509:")
}
