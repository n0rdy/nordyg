// Package msg converts miekg/dns messages into the contract's Message shape:
// typed record fields, parsed EDNS options, dig-style text.
package msg

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/bits"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/n0rdy/nordyg/core/internal/contract"
)

// Convert turns a parsed message into the contract shape. size is the wire
// size in bytes; pass 0 when unknown and the packed length is used.
func Convert(m *dns.Msg, size int) contract.Message {
	if size == 0 {
		size = m.Len()
	}
	out := contract.Message{
		ID:         m.Id,
		Opcode:     dns.OpcodeToString[m.Opcode],
		Rcode:      rcodeString(m.Rcode),
		Flags:      contract.Flags{QR: m.Response, AA: m.Authoritative, TC: m.Truncated, RD: m.RecursionDesired, RA: m.RecursionAvailable, AD: m.AuthenticatedData, CD: m.CheckingDisabled},
		Question:   make([]contract.Question, 0, len(m.Question)),
		Answer:     Records(m.Answer),
		Authority:  Records(m.Ns),
		Additional: make([]contract.Record, 0, len(m.Extra)),
		SizeBytes:  size,
		Text:       m.String(),
	}
	for _, q := range m.Question {
		out.Question = append(out.Question, contract.Question{Name: q.Name, Type: contract.TypeToString(q.Qtype), Class: dns.ClassToString[q.Qclass]})
	}
	for _, rr := range m.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			out.EDNS = convertEDNS(opt)
			continue
		}
		out.Additional = append(out.Additional, Record(rr))
	}
	return out
}

func rcodeString(rcode int) string {
	if s, ok := dns.RcodeToString[rcode]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rcode)
}

// Records converts a section. Never nil, so JSON shows [] not null.
func Records(rrs []dns.RR) []contract.Record {
	out := make([]contract.Record, 0, len(rrs))
	for _, rr := range rrs {
		if _, isOpt := rr.(*dns.OPT); isOpt {
			continue
		}
		out = append(out, Record(rr))
	}
	return out
}

// Record converts one RR.
func Record(rr dns.RR) contract.Record {
	h := rr.Header()
	rec := contract.Record{
		Name:     h.Name,
		Type:     contract.TypeToString(h.Rrtype),
		TypeCode: h.Rrtype,
		Class:    classString(h.Class),
		TTL:      h.Ttl,
		Rdata:    Rdata(rr),
	}
	if u, ok := rr.(*dns.RFC3597); ok {
		// miekg prints the header of unknown types with CLASS<n>, so the
		// generic prefix strip does not apply; build RFC 3597 form directly.
		rec.Raw = strings.ToLower(strings.ReplaceAll(u.Rdata, " ", ""))
		rec.Rdata = "\\# " + strconv.Itoa(len(rec.Raw)/2) + " " + u.Rdata
		return rec
	}
	rec.Fields = fields(rr)
	return rec
}

func classString(c uint16) string {
	if s, ok := dns.ClassToString[c]; ok {
		return s
	}
	return "CLASS" + strconv.Itoa(int(c))
}

// Rdata is the presentation-format rdata without the owner/TTL/class/type
// prefix, exactly as dig prints it.
func Rdata(rr dns.RR) string {
	s := rr.String()
	hdr := rr.Header().String()
	if strings.HasPrefix(s, hdr) {
		return strings.TrimSpace(s[len(hdr):])
	}
	return strings.TrimSpace(s)
}

func fields(rr dns.RR) map[string]any {
	switch r := rr.(type) {
	case *dns.A:
		return f{"address": r.A.String()}
	case *dns.AAAA:
		return f{"address": r.AAAA.String()}
	case *dns.NS:
		return f{"target": r.Ns}
	case *dns.CNAME:
		return f{"target": r.Target}
	case *dns.PTR:
		return f{"target": r.Ptr}
	case *dns.DNAME:
		return f{"target": r.Target}
	case *dns.MX:
		return f{"preference": r.Preference, "exchange": r.Mx}
	case *dns.SOA:
		return f{"mname": r.Ns, "rname": r.Mbox, "serial": r.Serial, "refresh": r.Refresh, "retry": r.Retry, "expire": r.Expire, "minimum": r.Minttl}
	case *dns.TXT:
		return f{"strings": r.Txt}
	case *dns.SPF:
		return f{"strings": r.Txt}
	case *dns.SRV:
		return f{"priority": r.Priority, "weight": r.Weight, "port": r.Port, "target": r.Target}
	case *dns.CAA:
		return f{"flags": r.Flag, "tag": r.Tag, "value": r.Value}
	case *dns.DS:
		return f{"key_tag": r.KeyTag, "algorithm": r.Algorithm, "algorithm_name": algName(r.Algorithm), "digest_type": r.DigestType, "digest_type_name": digestName(r.DigestType), "digest": strings.ToLower(r.Digest)}
	case *dns.DNSKEY:
		return f{"flags": r.Flags, "protocol": r.Protocol, "algorithm": r.Algorithm, "algorithm_name": algName(r.Algorithm), "public_key": r.PublicKey, "key_tag": r.KeyTag(), "role": keyRole(r.Flags), "bits": keyBits(r)}
	case *dns.RRSIG:
		return f{"type_covered": contract.TypeToString(r.TypeCovered), "algorithm": r.Algorithm, "algorithm_name": algName(r.Algorithm), "labels": r.Labels, "original_ttl": r.OrigTtl, "expiration": SerialTime(r.Expiration), "inception": SerialTime(r.Inception), "key_tag": r.KeyTag, "signer": r.SignerName, "signature": r.Signature}
	case *dns.NSEC:
		return f{"next": r.NextDomain, "types": typeNames(r.TypeBitMap)}
	case *dns.NSEC3:
		return f{"hash_algorithm": r.Hash, "flags": r.Flags, "iterations": r.Iterations, "salt": strings.ToLower(r.Salt), "next_hashed": r.NextDomain, "types": typeNames(r.TypeBitMap)}
	case *dns.NSEC3PARAM:
		return f{"hash_algorithm": r.Hash, "flags": r.Flags, "iterations": r.Iterations, "salt": strings.ToLower(r.Salt)}
	case *dns.TLSA:
		return f{"usage": r.Usage, "selector": r.Selector, "matching_type": r.MatchingType, "certificate_data": strings.ToLower(r.Certificate)}
	case *dns.SVCB:
		return svcbFields(r.Priority, r.Target, r.Value)
	case *dns.HTTPS:
		return svcbFields(r.Priority, r.Target, r.Value)
	case *dns.NAPTR:
		return f{"order": r.Order, "preference": r.Preference, "flags": r.Flags, "service": r.Service, "regexp": r.Regexp, "replacement": r.Replacement}
	case *dns.HINFO:
		return f{"cpu": r.Cpu, "os": r.Os}
	case *dns.SSHFP:
		return f{"algorithm": r.Algorithm, "type": r.Type, "fingerprint": strings.ToLower(r.FingerPrint)}
	}
	return nil
}

type f = map[string]any

func algName(a uint8) string {
	if s, ok := dns.AlgorithmToString[a]; ok {
		return s
	}
	return "ALG" + strconv.Itoa(int(a))
}

func digestName(d uint8) string {
	if s, ok := dns.HashToString[d]; ok {
		return s
	}
	return "DIGEST" + strconv.Itoa(int(d))
}

func keyRole(flags uint16) string {
	switch {
	case flags&dns.REVOKE != 0:
		return "revoked"
	case flags&dns.SEP != 0:
		return "ksk"
	case flags&dns.ZONE != 0:
		return "zsk"
	}
	return "other"
}

func keyBits(k *dns.DNSKEY) int {
	switch k.Algorithm {
	case dns.RSAMD5, dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512:
		return rsaBits(k.PublicKey)
	case dns.ECDSAP256SHA256:
		return 256
	case dns.ECDSAP384SHA384:
		return 384
	case dns.ED25519:
		return 256
	case dns.ED448:
		return 456
	}
	return 0
}

// rsaBits reads the modulus length from an RFC 3110 encoded RSA public key.
func rsaBits(b64 string) int {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) < 3 {
		return 0
	}
	expLen := int(raw[0])
	off := 1
	if expLen == 0 {
		if len(raw) < 3 {
			return 0
		}
		expLen = int(binary.BigEndian.Uint16(raw[1:3]))
		off = 3
	}
	mod := raw[off+expLen:]
	if len(mod) == 0 {
		return 0
	}
	// Strip leading zero bytes, then count significant bits.
	i := 0
	for i < len(mod)-1 && mod[i] == 0 {
		i++
	}
	return (len(mod)-i-1)*8 + bits.Len8(mod[i])
}

func typeNames(bitmap []uint16) []string {
	out := make([]string, 0, len(bitmap))
	for _, t := range bitmap {
		out = append(out, contract.TypeToString(t))
	}
	return out
}

func svcbFields(prio uint16, target string, kvs []dns.SVCBKeyValue) map[string]any {
	params := map[string]any{}
	for _, kv := range kvs {
		switch v := kv.(type) {
		case *dns.SVCBAlpn:
			params["alpn"] = v.Alpn
		case *dns.SVCBNoDefaultAlpn:
			params["no-default-alpn"] = true
		case *dns.SVCBPort:
			params["port"] = v.Port
		case *dns.SVCBIPv4Hint:
			params["ipv4hint"] = ipStrings(v.Hint)
		case *dns.SVCBIPv6Hint:
			params["ipv6hint"] = ipStrings(v.Hint)
		case *dns.SVCBECHConfig:
			params["ech"] = hex.EncodeToString(v.ECH)
		case *dns.SVCBMandatory:
			names := make([]string, 0, len(v.Code))
			for _, c := range v.Code {
				names = append(names, c.String())
			}
			params["mandatory"] = names
		case *dns.SVCBDoHPath:
			params["dohpath"] = v.Template
		case *dns.SVCBOhttp:
			params["ohttp"] = true
		case *dns.SVCBLocal:
			params[v.KeyCode.String()] = hex.EncodeToString(v.Data)
		default:
			params[kv.Key().String()] = kv.String()
		}
	}
	return f{"priority": prio, "target": target, "params": params}
}

func ipStrings(ips []net.IP) []string {
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// SerialTime converts an RRSIG inception/expiration (seconds since epoch mod
// 2^32, RFC 4034 §3.1.5) into an absolute time relative to now.
func SerialTime(serial uint32) time.Time {
	return serialTimeAt(serial, time.Now())
}

func serialTimeAt(serial uint32, now time.Time) time.Time {
	diff := int64(int32(serial - uint32(now.Unix())))
	return now.Add(time.Duration(diff) * time.Second).UTC().Truncate(time.Second)
}

func convertEDNS(opt *dns.OPT) *contract.EDNS {
	e := &contract.EDNS{
		Version:       opt.Version(),
		UDPSize:       opt.UDPSize(),
		DNSSECOK:      opt.Do(),
		ExtendedRcode: opt.ExtendedRcode(),
		Options:       make([]contract.EDNSOption, 0, len(opt.Option)),
	}
	for _, o := range opt.Option {
		e.Options = append(e.Options, convertOption(o))
	}
	return e
}

func convertOption(o dns.EDNS0) contract.EDNSOption {
	code := o.Option()
	out := contract.EDNSOption{Code: code, Name: optionName(code)}
	switch v := o.(type) {
	case *dns.EDNS0_EDE:
		out.EDE = &contract.EDE{InfoCode: v.InfoCode, Purpose: edePurpose(v.InfoCode), ExtraText: v.ExtraText}
		b := make([]byte, 2, 2+len(v.ExtraText))
		binary.BigEndian.PutUint16(b, v.InfoCode)
		out.Data = hex.EncodeToString(append(b, v.ExtraText...))
	case *dns.EDNS0_NSID:
		raw, _ := hex.DecodeString(v.Nsid)
		out.NSID = &contract.NSID{Text: printable(raw)}
		out.Data = strings.ToLower(v.Nsid)
	case *dns.EDNS0_COOKIE:
		c := strings.ToLower(v.Cookie)
		out.Cookie = &contract.Cookie{Client: c}
		if len(c) > 16 {
			out.Cookie.Client, out.Cookie.Server = c[:16], c[16:]
		}
		out.Data = c
	case *dns.EDNS0_SUBNET:
		out.ECS = &contract.ECS{Family: v.Family, SourcePrefix: v.SourceNetmask, ScopePrefix: v.SourceScope, Address: v.Address.String()}
		b := make([]byte, 4)
		binary.BigEndian.PutUint16(b, v.Family)
		b[2], b[3] = v.SourceNetmask, v.SourceScope
		addr := v.Address.To4()
		if v.Family == 2 {
			addr = v.Address.To16()
		}
		n := (int(v.SourceNetmask) + 7) / 8
		if addr != nil && n <= len(addr) {
			b = append(b, addr[:n]...)
		}
		out.Data = hex.EncodeToString(b)
	case *dns.EDNS0_LOCAL:
		out.Data = hex.EncodeToString(v.Data)
	default:
		// Anything else: render what miekg gives us; no raw bytes available.
		out.Data = ""
	}
	return out
}

func optionName(code uint16) string {
	switch code {
	case dns.EDNS0LLQ:
		return "LLQ"
	case dns.EDNS0UL:
		return "UL"
	case dns.EDNS0NSID:
		return "NSID"
	case dns.EDNS0DAU:
		return "DAU"
	case dns.EDNS0DHU:
		return "DHU"
	case dns.EDNS0N3U:
		return "N3U"
	case dns.EDNS0SUBNET:
		return "ECS"
	case dns.EDNS0EXPIRE:
		return "EXPIRE"
	case dns.EDNS0COOKIE:
		return "COOKIE"
	case dns.EDNS0TCPKEEPALIVE:
		return "TCP-KEEPALIVE"
	case dns.EDNS0PADDING:
		return "PADDING"
	case dns.EDNS0EDE:
		return "EDE"
	}
	return "OPT" + strconv.Itoa(int(code))
}

func edePurpose(code uint16) string {
	if s, ok := dns.ExtendedErrorCodeToString[code]; ok {
		return s
	}
	return "Unassigned"
}

func printable(b []byte) string {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return hex.EncodeToString(b)
		}
	}
	return string(b)
}
