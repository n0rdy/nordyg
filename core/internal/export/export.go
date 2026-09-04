// Package export implements the "export" op (contract §8): the CLI command
// equivalent to a query, for tickets and chats.
package export

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/n0rdy/nordyg/core/internal/bridge"
	"github.com/n0rdy/nordyg/core/internal/contract"
)

// Params is the op input.
type Params struct {
	Question contract.Question `json:"question"`
	Endpoint contract.Endpoint `json:"endpoint"`
	Options  contract.Options  `json:"options"`
	Format   string            `json:"format"`
}

// Result is the op output.
type Result struct {
	Command string `json:"command"`
}

// Register attaches the op to d.
func Register(d *bridge.Dispatcher) {
	d.Register("export", func(_ context.Context, raw json.RawMessage) (any, error) {
		var p Params
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, &bridge.Error{Code: bridge.CodeBadRequest, Message: "params: " + err.Error()}
		}
		cmd, err := Command(p)
		if err != nil {
			return nil, err
		}
		return Result{Command: cmd}, nil
	})
}

// Command builds the command line for the requested format.
func Command(p Params) (string, error) {
	r, err := p.Question.Resolve()
	if err != nil {
		return "", err
	}
	if err := p.Endpoint.Validate(); err != nil {
		return "", err
	}
	o := p.Options.Resolve()
	switch p.Format {
	case "dig":
		return dig(r, p.Endpoint, o)
	case "nslookup":
		return nslookup(r, p.Endpoint, o)
	case "doggo":
		return doggo(r, p.Endpoint, o)
	case "curl":
		return curl(r, p.Endpoint, o)
	}
	return "", &bridge.Error{Code: bridge.CodeBadRequest, Message: "format must be dig, nslookup, doggo or curl"}
}

func unsupported(tool, why string) error {
	return &bridge.Error{Code: contract.CodeExportUnsupported, Message: tool + " cannot express this query: " + why}
}

// name is the query name without the trailing dot unless it is the root.
func name(r contract.Resolved) string {
	if r.Name == "." {
		return "."
	}
	return strings.TrimSuffix(r.Name, ".")
}

func typeName(r contract.Resolved) string { return contract.TypeToString(r.Type) }

func hostPort(addr string) (string, string) {
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, ""
	}
	return h, p
}

// dig: BIND 9.18+ speaks DoT (+tls) and DoH (+https); DoQ is not supported.
func dig(r contract.Resolved, ep contract.Endpoint, o contract.Effective) (string, error) {
	args := []string{"dig"}
	switch ep.Transport {
	case contract.UDP, contract.TCP, contract.DoT:
		h, p := hostPort(ep.Address)
		args = append(args, "@"+h)
		if p != "" && p != defaultPort(ep.Transport) {
			args = append(args, "-p", p)
		}
	case contract.DoH:
		u, _ := url.Parse(ep.URL)
		args = append(args, "@"+u.Hostname())
		if p := u.Port(); p != "" && p != "443" {
			args = append(args, "-p", p)
		}
	case contract.DoQ:
		return "", unsupported("dig", "no DNS-over-QUIC support")
	}
	args = append(args, name(r), typeName(r))
	if r.Class != 1 {
		args = append(args, "-c", className(r.Class))
	}
	switch ep.Transport {
	case contract.TCP:
		args = append(args, "+tcp")
	case contract.DoT:
		args = append(args, "+tls")
		if ep.TLSName != "" {
			args = append(args, "+tls-hostname="+ep.TLSName)
		}
	case contract.DoH:
		u, _ := url.Parse(ep.URL)
		path := u.Path
		if path == "" || path == "/dns-query" {
			args = append(args, "+https")
		} else {
			args = append(args, "+https="+path)
		}
		if ep.Method == "get" {
			args = append(args, "+https-get")
		}
	}
	if !o.RecursionDesired {
		args = append(args, "+norecurse")
	}
	if !o.EDNS {
		args = append(args, "+noedns")
	} else {
		if o.DNSSECOK {
			args = append(args, "+dnssec")
		}
		if o.UDPSize != contract.DefaultUDPSize {
			args = append(args, "+bufsize="+strconv.Itoa(int(o.UDPSize)))
		}
		if o.NSID {
			args = append(args, "+nsid")
		}
		if o.Cookie {
			args = append(args, "+cookie")
		}
	}
	if o.CheckingDisabled {
		args = append(args, "+cdflag")
	}
	if o.Timeout != contract.DefaultTimeout {
		args = append(args, "+timeout="+strconv.Itoa(int(o.Timeout.Seconds())))
	}
	return join(args), nil
}

func nslookup(r contract.Resolved, ep contract.Endpoint, o contract.Effective) (string, error) {
	if ep.Transport != contract.UDP && ep.Transport != contract.TCP {
		return "", unsupported("nslookup", "only plain UDP/TCP")
	}
	args := []string{"nslookup", "-type=" + typeName(r)}
	if r.Class != 1 {
		args = append(args, "-class="+className(r.Class))
	}
	h, p := hostPort(ep.Address)
	if p != "" && p != "53" {
		args = append(args, "-port="+p)
	}
	if ep.Transport == contract.TCP {
		args = append(args, "-vc")
	}
	if !o.RecursionDesired {
		args = append(args, "-norecurse")
	}
	if o.Timeout != contract.DefaultTimeout {
		args = append(args, "-timeout="+strconv.Itoa(int(o.Timeout.Seconds())))
	}
	args = append(args, name(r), h)
	return join(args), nil
}

func doggo(r contract.Resolved, ep contract.Endpoint, o contract.Effective) (string, error) {
	args := []string{"doggo", name(r), typeName(r)}
	if r.Class != 1 {
		args = append(args, className(r.Class))
	}
	switch ep.Transport {
	case contract.UDP:
		args = append(args, "@udp://"+ep.Address)
	case contract.TCP:
		args = append(args, "@tcp://"+ep.Address)
	case contract.DoT:
		args = append(args, "@tls://"+ep.Address, "--tls-hostname="+ep.TLSName)
	case contract.DoH:
		args = append(args, "@"+ep.URL)
	case contract.DoQ:
		args = append(args, "@quic://"+ep.Address, "--tls-hostname="+ep.TLSName)
	}
	if o.Timeout != contract.DefaultTimeout {
		args = append(args, "--timeout="+o.Timeout.String())
	}
	return join(args), nil
}

// curl speaks DoH only: GET with the packed query in the dns parameter.
func curl(r contract.Resolved, ep contract.Endpoint, o contract.Effective) (string, error) {
	if ep.Transport != contract.DoH {
		return "", unsupported("curl", "only DNS-over-HTTPS")
	}
	q := o.Build(r)
	q.Id = 0
	packed, err := q.Pack()
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(ep.URL)
	qs := u.Query()
	qs.Set("dns", base64.RawURLEncoding.EncodeToString(packed))
	u.RawQuery = qs.Encode()
	args := []string{"curl", "-s", "-H", "accept: application/dns-message"}
	if ep.Address != "" {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		ip, _ := hostPort(ep.Address)
		args = append(args, "--resolve", u.Hostname()+":"+port+":"+ip)
	}
	args = append(args, u.String(), "-o", "dns-response.bin")
	return join(args), nil
}

func defaultPort(transport string) string {
	if transport == contract.DoT || transport == contract.DoQ {
		return "853"
	}
	return "53"
}

func className(c uint16) string {
	switch c {
	case 3:
		return "CH"
	case 4:
		return "HS"
	}
	return "IN"
}

// join shell-quotes arguments that need it.
func join(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = quote(a)
	}
	return strings.Join(out, " ")
}

func quote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.ContainsAny(s, " \t\n'\"\\$`&|;<>(){}[]*?!#~") {
		return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
	}
	return s
}
