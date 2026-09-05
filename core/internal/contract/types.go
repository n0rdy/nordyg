// Package contract holds the JSON types shared by every op, mirroring
// context/contract.md §2. Keep field names and semantics in sync with that file.
package contract

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/bridge"
)

// Transports.
const (
	UDP = "udp"
	TCP = "tcp"
	DoT = "dot"
	DoH = "doh"
	DoQ = "doq"
)

// Op-level error codes (contract §9).
const (
	CodeUnknownType       = "unknown_type"
	CodeBadEndpoint       = "bad_endpoint"
	CodeBootstrapRequired = "bootstrap_required"
	CodeBootstrapFailed   = "bootstrap_failed"
	CodeTimeout           = "timeout"
	CodeNetwork           = "network"
	CodeTLS               = "tls"
	CodeHTTP              = "http"
	CodeMalformed         = "malformed_response"
	CodeTraceDeadEnd      = "trace_dead_end"
	CodeExportUnsupported = "export_unsupported"
)

// JoinHostPort formats an IP literal and a port as an endpoint address.
func JoinHostPort(ip string, port int) string {
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

// Endpoint is where and how to send a query (§2.1).
type Endpoint struct {
	Transport string `json:"transport"`
	Address   string `json:"address,omitempty"`
	TLSName   string `json:"tls_name,omitempty"`
	URL       string `json:"url,omitempty"`
	Method    string `json:"method,omitempty"`
	Label     string `json:"label,omitempty"`
}

// Validate checks the fields required for the endpoint's transport.
func (e Endpoint) Validate() error {
	bad := func(msg string) error {
		return &bridge.Error{Code: CodeBadEndpoint, Message: msg}
	}
	if e.Address != "" {
		host, _, err := net.SplitHostPort(e.Address)
		if err != nil {
			return bad("address must be ip:port: " + err.Error())
		}
		if net.ParseIP(host) == nil {
			return bad("address host must be an IP literal, got " + host)
		}
	}
	switch e.Transport {
	case UDP, TCP:
		if e.Address == "" {
			return bad("address is required for " + e.Transport)
		}
	case DoT, DoQ:
		if e.Address == "" {
			return bad("address is required for " + e.Transport)
		}
		if e.TLSName == "" {
			return bad("tls_name is required for " + e.Transport)
		}
	case DoH:
		if e.URL == "" {
			return bad("url is required for doh")
		}
		u, err := url.Parse(e.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return bad("url must be an https URL with a host")
		}
		switch e.Method {
		case "", "post", "get":
		default:
			return bad("method must be post or get")
		}
	case "":
		return bad("transport is required")
	default:
		return bad("unknown transport " + e.Transport)
	}
	return nil
}

// Question is what to ask (§2.2).
type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class,omitempty"`
}

// Resolved is a Question turned into wire values, with the name the core will
// actually send (reverse name for PTR of an IP, fully qualified).
type Resolved struct {
	Name  string
	Type  uint16
	Class uint16
}

// Question returns the resolved question in JSON form for question_sent.
func (r Resolved) Question() Question {
	return Question{Name: r.Name, Type: TypeToString(r.Type), Class: dns.ClassToString[r.Class]}
}

var typeN = regexp.MustCompile(`^TYPE(\d{1,5})$`)

// ParseType accepts a mnemonic or TYPE<n>, case-insensitively.
func ParseType(s string) (uint16, error) {
	up := strings.ToUpper(strings.TrimSpace(s))
	if t, ok := dns.StringToType[up]; ok {
		return t, nil
	}
	if m := typeN.FindStringSubmatch(up); m != nil {
		n, err := strconv.Atoi(m[1])
		if err == nil && n <= 0xFFFF {
			return uint16(n), nil
		}
	}
	return 0, &bridge.Error{Code: CodeUnknownType, Message: "unknown record type " + s}
}

// TypeToString renders a type as its mnemonic or TYPE<n>.
func TypeToString(t uint16) string {
	if s, ok := dns.TypeToString[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// Resolve validates the question and applies the PTR-of-IP rule.
func (q Question) Resolve() (Resolved, error) {
	if strings.TrimSpace(q.Name) == "" {
		return Resolved{}, &bridge.Error{Code: bridge.CodeBadRequest, Message: "question.name is required"}
	}
	if strings.TrimSpace(q.Type) == "" {
		return Resolved{}, &bridge.Error{Code: bridge.CodeBadRequest, Message: "question.type is required"}
	}
	t, err := ParseType(q.Type)
	if err != nil {
		return Resolved{}, err
	}
	class := uint16(dns.ClassINET)
	if q.Class != "" {
		c, ok := dns.StringToClass[strings.ToUpper(q.Class)]
		if !ok {
			return Resolved{}, &bridge.Error{Code: bridge.CodeBadRequest, Message: "unknown class " + q.Class}
		}
		class = c
	}
	name := strings.TrimSpace(q.Name)
	if t == dns.TypePTR {
		if ip := net.ParseIP(name); ip != nil {
			rev, err := dns.ReverseAddr(name)
			if err != nil {
				return Resolved{}, &bridge.Error{Code: bridge.CodeBadRequest, Message: err.Error()}
			}
			name = rev
		}
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return Resolved{}, &bridge.Error{Code: bridge.CodeBadRequest, Message: "invalid domain name " + q.Name}
	}
	return Resolved{Name: dns.Fqdn(name), Type: t, Class: class}, nil
}

// Options are the per-query knobs (§2.3). Pointer bools distinguish "absent"
// from "false" so the true-by-default ones work.
type Options struct {
	RecursionDesired *bool `json:"recursion_desired,omitempty"`
	DNSSECOK         *bool `json:"dnssec_ok,omitempty"`
	CheckingDisabled *bool `json:"checking_disabled,omitempty"`
	EDNS             *bool `json:"edns,omitempty"`
	UDPSize          int   `json:"udp_size,omitempty"`
	TCPFallback      *bool `json:"tcp_fallback,omitempty"`
	TimeoutMS        int   `json:"timeout_ms,omitempty"`
	NSID             bool  `json:"nsid,omitempty"`
	Cookie           bool  `json:"cookie,omitempty"`
}

// Effective is Options with defaults applied.
type Effective struct {
	RecursionDesired bool
	DNSSECOK         bool
	CheckingDisabled bool
	EDNS             bool
	UDPSize          uint16
	TCPFallback      bool
	Timeout          time.Duration
	NSID             bool
	Cookie           bool
}

const (
	DefaultUDPSize = 1232
	DefaultTimeout = 5 * time.Second
)

func orTrue(b *bool) bool { return b == nil || *b }

// Resolve applies defaults.
func (o Options) Resolve() Effective {
	e := Effective{
		RecursionDesired: orTrue(o.RecursionDesired),
		DNSSECOK:         orTrue(o.DNSSECOK),
		CheckingDisabled: o.CheckingDisabled != nil && *o.CheckingDisabled,
		EDNS:             orTrue(o.EDNS),
		UDPSize:          DefaultUDPSize,
		TCPFallback:      orTrue(o.TCPFallback),
		Timeout:          DefaultTimeout,
		NSID:             o.NSID,
		Cookie:           o.Cookie,
	}
	if o.UDPSize > 0 && o.UDPSize <= 0xFFFF {
		e.UDPSize = uint16(o.UDPSize)
	}
	if o.TimeoutMS > 0 {
		e.Timeout = time.Duration(o.TimeoutMS) * time.Millisecond
	}
	if !e.EDNS {
		e.DNSSECOK = false
		e.NSID = false
		e.Cookie = false
	}
	return e
}

// Build creates the wire query for a resolved question and options.
func (e Effective) Build(r Resolved) *dns.Msg {
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.Question = []dns.Question{{Name: r.Name, Qtype: r.Type, Qclass: r.Class}}
	m.RecursionDesired = e.RecursionDesired
	m.CheckingDisabled = e.CheckingDisabled
	if e.EDNS {
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.SetUDPSize(e.UDPSize)
		opt.SetDo(e.DNSSECOK)
		if e.NSID {
			opt.Option = append(opt.Option, &dns.EDNS0_NSID{Code: dns.EDNS0NSID})
		}
		if e.Cookie {
			opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: randomCookie()})
		}
		m.Extra = append(m.Extra, opt)
	}
	return m
}

// Flags mirrors the header bits (§2.4).
type Flags struct {
	QR bool `json:"qr"`
	AA bool `json:"aa"`
	TC bool `json:"tc"`
	RD bool `json:"rd"`
	RA bool `json:"ra"`
	AD bool `json:"ad"`
	CD bool `json:"cd"`
}

// EDNSOption is one OPT option with an optional parsed sibling.
type EDNSOption struct {
	Code   uint16  `json:"code"`
	Name   string  `json:"name"`
	Data   string  `json:"data"`
	EDE    *EDE    `json:"ede,omitempty"`
	NSID   *NSID   `json:"nsid,omitempty"`
	Cookie *Cookie `json:"cookie,omitempty"`
	ECS    *ECS    `json:"ecs,omitempty"`
}

// EDE is RFC 8914 extended DNS error.
type EDE struct {
	InfoCode  uint16 `json:"info_code"`
	Purpose   string `json:"purpose"`
	ExtraText string `json:"extra_text"`
}

// NSID is the server identifier as text (RFC 5001).
type NSID struct {
	Text string `json:"text"`
}

// Cookie is RFC 7873 client/server cookie, hex.
type Cookie struct {
	Client string `json:"client"`
	Server string `json:"server,omitempty"`
}

// ECS is RFC 7871 client subnet.
type ECS struct {
	Family       uint16 `json:"family"`
	SourcePrefix uint8  `json:"source_prefix"`
	ScopePrefix  uint8  `json:"scope_prefix"`
	Address      string `json:"address"`
}

// EDNS is the parsed OPT pseudo-record.
type EDNS struct {
	Version       uint8        `json:"version"`
	UDPSize       uint16       `json:"udp_size"`
	DNSSECOK      bool         `json:"dnssec_ok"`
	ExtendedRcode int          `json:"extended_rcode"`
	Options       []EDNSOption `json:"options"`
}

// Record is one resource record (§2.5).
type Record struct {
	Name     string         `json:"name"`
	Type     string         `json:"type"`
	TypeCode uint16         `json:"type_code"`
	Class    string         `json:"class"`
	TTL      uint32         `json:"ttl"`
	Rdata    string         `json:"rdata"`
	Fields   map[string]any `json:"fields,omitempty"`
	Raw      string         `json:"raw,omitempty"`
	Decoded  any            `json:"decoded,omitempty"`
}

// Message is a parsed DNS message (§2.4).
type Message struct {
	ID         uint16     `json:"id"`
	Opcode     string     `json:"opcode"`
	Rcode      string     `json:"rcode"`
	Flags      Flags      `json:"flags"`
	Question   []Question `json:"question"`
	Answer     []Record   `json:"answer"`
	Authority  []Record   `json:"authority"`
	Additional []Record   `json:"additional"`
	EDNS       *EDNS      `json:"edns"`
	SizeBytes  int        `json:"size_bytes"`
	Text       string     `json:"text"`
}

// Certificate summarises the leaf certificate of a TLS session.
type Certificate struct {
	Subject   string    `json:"subject"`
	Issuer    string    `json:"issuer"`
	DNSNames  []string  `json:"dns_names"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
}

// TLSInfo describes the TLS session of a dot/doh/doq exchange (§2.6).
type TLSInfo struct {
	Version     string       `json:"version"`
	CipherSuite string       `json:"cipher_suite"`
	ServerName  string       `json:"server_name"`
	ALPN        string       `json:"alpn"`
	HandshakeMS float64      `json:"handshake_ms"`
	Certificate *Certificate `json:"certificate,omitempty"`
}

// HTTPInfo describes the HTTP layer of a doh exchange.
type HTTPInfo struct {
	Status      int    `json:"status"`
	Version     string `json:"version"`
	ContentType string `json:"content_type"`
}

// Exchange is what happened on the wire for one message (§2.6).
type Exchange struct {
	Endpoint       Endpoint  `json:"endpoint"`
	Protocol       string    `json:"protocol"`
	TruncatedRetry bool      `json:"truncated_retry"`
	RTTms          float64   `json:"rtt_ms"`
	StartedAt      time.Time `json:"started_at"`
	TLS            *TLSInfo  `json:"tls,omitempty"`
	HTTP           *HTTPInfo `json:"http,omitempty"`
}
