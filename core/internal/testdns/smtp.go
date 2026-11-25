package testdns

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
	"testing"
)

// SMTP starts a mail server that speaks just enough SMTP to greet, answer
// EHLO, and (when starttls is set) upgrade to TLS presenting cert. It returns
// its ip:port.
func SMTP(t testing.TB, cert tls.Certificate, starttls bool) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveSMTP(c, cert, starttls)
		}
	}()
	return l.Addr().String()
}

func serveSMTP(c net.Conn, cert tls.Certificate, starttls bool) {
	defer func() { _ = c.Close() }()
	r := bufio.NewReader(c)
	_, _ = c.Write([]byte("220 mx.example.test ESMTP\r\n"))
	upgraded := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		switch cmd := strings.ToUpper(strings.TrimSpace(line)); {
		case strings.HasPrefix(cmd, "EHLO"):
			if starttls && !upgraded {
				_, _ = c.Write([]byte("250-mx.example.test\r\n250 STARTTLS\r\n"))
			} else {
				_, _ = c.Write([]byte("250 mx.example.test\r\n"))
			}
		case cmd == "STARTTLS" && starttls && !upgraded:
			_, _ = c.Write([]byte("220 go ahead\r\n"))
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{cert}})
			if tc.Handshake() != nil {
				return
			}
			c, r, upgraded = tc, bufio.NewReader(tc), true
		case cmd == "QUIT":
			_, _ = c.Write([]byte("221 bye\r\n"))
			return
		default:
			_, _ = c.Write([]byte("500 unrecognised command\r\n"))
		}
	}
}
