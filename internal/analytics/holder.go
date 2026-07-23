package analytics

import "sync/atomic"

// NormalizerHolder holds the current Normalizer behind an atomic pointer so it
// can be hot-swapped when route patterns change, without restarting the tailers
// that use it. Tailers call Normalize per line and always see the latest rules.
type NormalizerHolder struct {
	p atomic.Pointer[Normalizer]
}

// NewNormalizerHolder starts with a pure-heuristic (no patterns) normalizer.
func NewNormalizerHolder() *NormalizerHolder {
	h := &NormalizerHolder{}
	h.p.Store(NewNormalizer(nil, nil))
	return h
}

// Store swaps in a new normalizer.
func (h *NormalizerHolder) Store(n *Normalizer) { h.p.Store(n) }

// Normalize applies the current normalizer.
func (h *NormalizerHolder) Normalize(path string) string { return h.p.Load().Normalize(path) }

// Ignore reports whether the current normalizer would drop this path from
// ingestion (see Normalizer.Ignore).
func (h *NormalizerHolder) Ignore(path string) bool { return h.p.Load().Ignore(path) }
