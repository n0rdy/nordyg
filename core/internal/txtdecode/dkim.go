package txtdecode

import (
	"crypto/ed25519"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"strconv"
	"strings"
)

// DKIMTags are the parsed tags.
type DKIMTags struct {
	V *string `json:"v"`
	K *string `json:"k"`
	H *string `json:"h"`
	T *string `json:"t"`
	S *string `json:"s"`
	N *string `json:"n"`
}

// DKIM is a decoded DKIM public key record.
type DKIM struct {
	Kind     string    `json:"kind"`
	Tags     DKIMTags  `json:"tags"`
	KeyType  string    `json:"key_type"`
	KeyBits  int       `json:"key_bits"`
	Revoked  bool      `json:"revoked"`
	Problems []Problem `json:"problems"`
}

// DecodeDKIM parses a DKIM key record (RFC 6376 §3.6.1).
func DecodeDKIM(txt string) *DKIM {
	out := &DKIM{Kind: "dkim", Problems: []Problem{}, KeyType: "rsa"}
	tags, order := parseTags(txt)
	var pubB64 string
	hasP := false
	for _, k := range order {
		v := tags[k]
		switch k {
		case "v":
			out.Tags.V = ptr(v)
			if !strings.EqualFold(v, "DKIM1") {
				out.Problems = append(out.Problems, Problem{SevError, "v must be DKIM1, got " + v})
			}
		case "k":
			out.Tags.K = ptr(v)
			out.KeyType = strings.ToLower(v)
		case "h":
			out.Tags.H = ptr(v)
		case "t":
			out.Tags.T = ptr(v)
			for _, flag := range splitList(v) {
				switch strings.ToLower(flag) {
				case "y":
					out.Problems = append(out.Problems, Problem{SevInfo, "t=y marks the domain as testing, so verifiers treat failures leniently"})
				case "s":
				default:
					out.Problems = append(out.Problems, Problem{SevWarning, "unknown t flag " + flag})
				}
			}
		case "s":
			out.Tags.S = ptr(v)
		case "n":
			out.Tags.N = ptr(v)
		case "p":
			hasP = true
			pubB64 = strings.Join(strings.Fields(v), "")
		default:
			out.Problems = append(out.Problems, Problem{SevWarning, "unknown tag " + k})
		}
	}
	if out.Tags.V != nil && order[0] != "v" {
		out.Problems = append(out.Problems, Problem{SevWarning, "v tag must be first when present"})
	}
	if !hasP {
		out.Problems = append(out.Problems, Problem{SevError, "p tag is required"})
		return out
	}
	if pubB64 == "" {
		out.Revoked = true
		out.Problems = append(out.Problems, Problem{SevInfo, "empty p= means the key is revoked"})
		return out
	}
	raw, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		out.Problems = append(out.Problems, Problem{SevError, "p is not valid base64: " + err.Error()})
		return out
	}
	switch out.KeyType {
	case "rsa":
		bitsN := rsaBits(raw)
		if bitsN == 0 {
			out.Problems = append(out.Problems, Problem{SevError, "p does not decode as an RSA public key"})
			return out
		}
		out.KeyBits = bitsN
		switch {
		case bitsN < 1024:
			out.Problems = append(out.Problems, Problem{SevError, "RSA key is " + strconv.Itoa(bitsN) + " bits, and verifiers reject keys under 1024 (RFC 8301)"})
		case bitsN < 2048:
			out.Problems = append(out.Problems, Problem{SevWarning, "RSA key is " + strconv.Itoa(bitsN) + " bits, but 2048 is recommended"})
		}
	case "ed25519":
		if len(raw) != ed25519.PublicKeySize {
			out.Problems = append(out.Problems, Problem{SevError, "ed25519 key must be 32 bytes, got " + strconv.Itoa(len(raw))})
			return out
		}
		out.KeyBits = 256
	default:
		out.Problems = append(out.Problems, Problem{SevError, "unknown key type " + out.KeyType})
	}
	return out
}

// rsaBits reads the modulus size from a PKIX (SubjectPublicKeyInfo) or PKCS#1
// encoded RSA key. It parses the ASN.1 directly so keys Go's crypto package
// rejects as too small are still measured; that is exactly the case worth
// reporting.
func rsaBits(der []byte) int {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	pkcs1 := der
	if rest, err := asn1.Unmarshal(der, &spki); err == nil && len(rest) == 0 {
		pkcs1 = spki.PublicKey.RightAlign()
	}
	var key struct {
		N *big.Int
		E int
	}
	if rest, err := asn1.Unmarshal(pkcs1, &key); err != nil || len(rest) != 0 || key.N == nil {
		return 0
	}
	return key.N.BitLen()
}
