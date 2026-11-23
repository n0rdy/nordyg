// Package dnssec validates answers against the root trust anchors and reports
// the chain link by link (contract §2.7). It never trusts a resolver's AD bit.
package dnssec

import "time"

// Statuses.
const (
	Secure        = "secure"
	Insecure      = "insecure"
	Bogus         = "bogus"
	Indeterminate = "indeterminate"
)

// KeyRef identifies a DNSKEY.
type KeyRef struct {
	KeyTag        uint16 `json:"key_tag"`
	Algorithm     uint8  `json:"algorithm"`
	AlgorithmName string `json:"algorithm_name"`
	Role          string `json:"role"`
	TrustAnchor   bool   `json:"trust_anchor,omitempty"`
}

// DSRef identifies a DS and whether a DNSKEY matched it.
type DSRef struct {
	KeyTag        uint16 `json:"key_tag"`
	Algorithm     uint8  `json:"algorithm"`
	DigestType    uint8  `json:"digest_type"`
	MatchesDNSKEY bool   `json:"matches_dnskey"`
}

// Signature is one RRSIG and its verification outcome.
type Signature struct {
	TypeCovered string    `json:"type_covered"`
	Name        string    `json:"name"`
	KeyTag      uint16    `json:"key_tag"`
	Algorithm   uint8     `json:"algorithm"`
	Signer      string    `json:"signer"`
	Inception   time.Time `json:"inception"`
	Expiration  time.Time `json:"expiration"`
	Valid       bool      `json:"valid"`
	Error       string    `json:"error,omitempty"`
	ExpiresInMS int64     `json:"expires_in_ms"`
}

// Link is one zone in the chain.
type Link struct {
	Zone       string      `json:"zone"`
	Status     string      `json:"status"`
	Reason     string      `json:"reason,omitempty"`
	DNSKeys    []KeyRef    `json:"dnskeys"`
	DS         []DSRef     `json:"ds"`
	Signatures []Signature `json:"signatures"`
}

// Result is the verdict for one answer.
type Result struct {
	Status           string      `json:"status"`
	Reason           string      `json:"reason"`
	TrustAnchor      *KeyRef     `json:"trust_anchor"`
	Chain            []Link      `json:"chain"`
	AnswerSignatures []Signature `json:"answer_signatures"`
	Related          []Related   `json:"related"`
}

// Related is the chain for an answer RRset signed by a zone other than the
// queried name's (a CNAME into another zone), validated from the root on its
// own. Status folds into the parent Result's status.
type Related struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Signer string `json:"signer"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	Chain  []Link `json:"chain"`
}
