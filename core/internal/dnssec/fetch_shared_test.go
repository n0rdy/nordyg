package dnssec

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

type countingFetcher struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (c *countingFetcher) Fetch(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return nil, errors.New("timeout")
	}
	m := new(dns.Msg)
	m.SetQuestion(name, qtype)
	return m, nil
}

func TestSharedFetchesOnce(t *testing.T) {
	c := &countingFetcher{}
	f := Shared(c)
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = f.Fetch(context.Background(), "Example.COM", dns.TypeDNSKEY) }()
	}
	wg.Wait()
	if n := c.calls.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
	// Failures are not kept.
	c.fail.Store(true)
	_, err1 := f.Fetch(context.Background(), "a.example.", dns.TypeA)
	c.fail.Store(false)
	m, err2 := f.Fetch(context.Background(), "a.example.", dns.TypeA)
	if err1 == nil || err2 != nil || m == nil {
		t.Fatalf("%v %v", err1, err2)
	}
}

func TestFetchRRsetRetriesServfail(t *testing.T) {
	n := 0
	f := fetcherFunc(func(_ context.Context, name string, qtype uint16) (*dns.Msg, error) {
		n++
		m := new(dns.Msg)
		m.SetQuestion(name, qtype)
		if n == 1 {
			m.Rcode = dns.RcodeServerFailure
		}
		return m, nil
	})
	if _, err := FetchRRset(context.Background(), f, "a.example.", dns.TypeTLSA); err != nil || n != 2 {
		t.Fatalf("err %v after %d tries", err, n)
	}
}

type fetcherFunc func(context.Context, string, uint16) (*dns.Msg, error)

func (f fetcherFunc) Fetch(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	return f(ctx, name, qtype)
}
