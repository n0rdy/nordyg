// Package transport sends one DNS message to one endpoint over udp, tcp, dot,
// doh or doq and reports what happened on the wire (contract §2.1, §2.6).
package transport

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"strconv"
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

// --- udp / tcp / dot -------------------------------------------------------

func (c *Client) udp(ctx context.Context, ep contract.Endpoint, q *dns.Msg, o contract.Effective) (*Result, error) {
	d := &net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", ep.Address)
	if err != nil {
		return nil, err
	}
	co := &dns.Conn{Conn: conn, UDPSize: max(o.UDPSize, dns.MinMsgSize)}
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

// --- doh --------------------------------------------------------------------

func (c *Client) doh(ctx context.Context, ep contract.Endpoint, q *dns.Msg, o contract.Effective, bootstrap []contract.Endpoint) (*Result, error) {
	u, err := url.Parse(ep.URL)
	if err != nil {
		return nil, err
	}
	dialAddr := ep.Address
	if dialAddr == "" {
		ip, err := c.resolveHost(ctx, u.Hostname(), o, bootstrap)
		if err != nil {
			return nil, err
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		dialAddr = net.JoinHostPort(ip, port)
	}
	tlsName := ep.TLSName
	if tlsName == "" {
		tlsName = u.Hostname()
	}

	tr := &http.Transport{
		TLSClientConfig:   &tls.Config{ServerName: tlsName, RootCAs: c.RootCAs, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, dialAddr)
		},
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	// RFC 8484 §4.1: id 0 for cache friendliness.
	sendq := q.Copy()
	sendq.Id = 0
	packed, err := sendq.Pack()
	if err != nil {
		return nil, err
	}

	var req *http.Request
	if ep.Method == "get" {
		gu := *u
		qs := gu.Query()
		qs.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
		gu.RawQuery = qs.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, gu.String(), nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(packed))
		if err == nil {
			req.Header.Set("Content-Type", "application/dns-message")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "nordyg")

	var hsStart time.Time
	var hs time.Duration
	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		TLSHandshakeStart: func() { hsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { hs = time.Since(hsStart) },
	}))

	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		return nil, err
	}
	info := &contract.HTTPInfo{Status: resp.StatusCode, Version: resp.Proto, ContentType: resp.Header.Get("Content-Type")}
	if resp.StatusCode != http.StatusOK {
		return nil, &bridge.Error{Code: contract.CodeHTTP, Message: fmt.Sprintf("DoH server returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(truncate(body, 200)))), Details: map[string]any{"status": resp.StatusCode}}
	}
	if ct := strings.ToLower(info.ContentType); !strings.HasPrefix(ct, "application/dns-message") {
		return nil, &bridge.Error{Code: contract.CodeHTTP, Message: "DoH server returned content type " + info.ContentType, Details: map[string]any{"status": resp.StatusCode}}
	}
	r := new(dns.Msg)
	if err := r.Unpack(body); err != nil {
		return nil, malformed(err)
	}
	res := &Result{Msg: r, Size: len(body)}
	res.Exchange.Protocol = contract.DoH
	res.Exchange.HTTP = info
	if resp.TLS != nil {
		res.Exchange.TLS = tlsInfo(*resp.TLS, hs)
	}
	return res, nil
}

func truncate(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// resolveHost turns a DoH hostname into an IP using the bootstrap endpoints.
func (c *Client) resolveHost(ctx context.Context, host string, o contract.Effective, bootstrap []contract.Endpoint) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}
	if len(bootstrap) == 0 {
		return "", &bridge.Error{Code: contract.CodeBootstrapRequired, Message: "DoH host " + host + " needs an address or bootstrap resolvers"}
	}
	var lastErr error
	for _, b := range bootstrap {
		if b.Transport != contract.UDP && b.Transport != contract.TCP {
			continue
		}
		for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(host), t)
			m.SetEdns0(contract.DefaultUDPSize, false)
			res, err := c.Exchange(ctx, b, m, o, nil)
			if err != nil {
				lastErr = err
				continue
			}
			for _, rr := range res.Msg.Answer {
				switch a := rr.(type) {
				case *dns.A:
					return a.A.String(), nil
				case *dns.AAAA:
					return a.AAAA.String(), nil
				}
			}
		}
	}
	msg := "no address for " + host + " from bootstrap resolvers"
	if lastErr != nil {
		msg += ": " + lastErr.Error()
	}
	return "", &bridge.Error{Code: contract.CodeBootstrapFailed, Message: msg}
}

// --- doq --------------------------------------------------------------------

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

// --- shared -------------------------------------------------------------------

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

// Addr formats an ip and port for endpoint addresses.
func Addr(ip string, port int) string { return net.JoinHostPort(ip, strconv.Itoa(port)) }
