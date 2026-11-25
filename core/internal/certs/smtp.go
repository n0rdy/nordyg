package certs

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/smtp"
	"time"
)

// ErrNoSTARTTLS means the mail server answered but did not offer STARTTLS.
var ErrNoSTARTTLS = errors.New("the server does not offer STARTTLS")

// DialError wraps a failure to reach the server at all, as opposed to a
// server that answered and then failed. Port 25 is often blocked by the
// network the Mac is on, so callers treat the two differently.
type DialError struct{ Err error }

func (e *DialError) Error() string { return e.Err.Error() }
func (e *DialError) Unwrap() error { return e.Err }

// HandshakeSMTP connects to a mail server at addr, upgrades the session with
// STARTTLS for sni and returns the TLS state without verifying anything.
// The connect is bounded by the inspector's timeout (3 s by default): a
// reachable server accepts in milliseconds, and networks that block port 25
// usually drop the packets, so waiting longer only makes the check slow.
// Once connected, mail servers can be slow to greet, so the session gets
// three times as long.
func (in *Inspector) HandshakeSMTP(ctx context.Context, addr, sni string) (*tls.ConnectionState, error) {
	timeout := in.Timeout
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, 4*timeout)
	defer cancel()
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &DialError{err}
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	c, err := smtp.NewClient(conn, sni)
	if err != nil {
		return nil, err
	}
	if err := c.Hello("nordyg.invalid"); err != nil {
		return nil, err
	}
	if ok, _ := c.Extension("STARTTLS"); !ok {
		_ = c.Quit()
		return nil, ErrNoSTARTTLS
	}
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,             // DANE matches the chain against TLSA records, not a trust store
		MinVersion:         tls.VersionTLS10, // an old server is something to report, not a reason to see nothing
	}
	if err := c.StartTLS(cfg); err != nil {
		return nil, err
	}
	st, _ := c.TLSConnectionState()
	_ = c.Quit()
	return &st, nil
}
