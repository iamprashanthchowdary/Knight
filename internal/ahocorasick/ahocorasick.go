// Package ahocorasick implements the Aho-Corasick multi-pattern string
// matching algorithm.
//
// Why this matters for Knight: a WAF may carry hundreds of signature rules.
// Running every rule's regex against every request is O(rules * len). Instead
// we compile the cheap literal "keywords" of every rule into ONE automaton and
// scan each request a single time in O(len + matches). Only rules whose keyword
// actually appears in the request become candidates for the (more expensive)
// regex confirmation step. This is the core of Knight's "observe fast, strike
// only when needed" design.
//
// The Matcher is built once at startup and is safe for concurrent reads.
package ahocorasick

type node struct {
	children map[byte]*node
	fail     *node
	// outputs holds every pattern that ends at this node, already merged with
	// the outputs reachable through fail links so matching needs no extra walk.
	outputs []string
}

// Matcher is an immutable Aho-Corasick automaton.
type Matcher struct {
	root  *node
	empty bool // true when no patterns were supplied
}

// New builds an automaton from the given patterns. Empty patterns are ignored.
// Patterns should already be normalized (e.g. lower-cased) by the caller so the
// scan text can be normalized the same way.
func New(patterns []string) *Matcher {
	root := &node{children: map[byte]*node{}}
	count := 0
	for _, p := range patterns {
		if p == "" {
			continue
		}
		count++
		cur := root
		for i := 0; i < len(p); i++ {
			c := p[i]
			nx := cur.children[c]
			if nx == nil {
				nx = &node{children: map[byte]*node{}}
				cur.children[c] = nx
			}
			cur = nx
		}
		cur.outputs = append(cur.outputs, p)
	}

	// Breadth-first construction of fail links.
	queue := make([]*node, 0, 64)
	for _, ch := range root.children {
		ch.fail = root
		queue = append(queue, ch)
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for c, ch := range cur.children {
			queue = append(queue, ch)
			f := cur.fail
			for f != nil && f.children[c] == nil {
				f = f.fail
			}
			if f == nil {
				ch.fail = root
			} else {
				ch.fail = f.children[c]
			}
			// ch.fail is shallower and (BFS order) already fully merged.
			ch.outputs = append(ch.outputs, ch.fail.outputs...)
		}
	}

	return &Matcher{root: root, empty: count == 0}
}

// Match returns the set of distinct patterns found anywhere in text.
// It performs a single left-to-right scan.
func (m *Matcher) Match(text string) []string {
	if m.empty {
		return nil
	}
	var res []string
	var seen map[string]struct{}
	cur := m.root
	for i := 0; i < len(text); i++ {
		c := text[i]
		for cur != m.root && cur.children[c] == nil {
			cur = cur.fail
		}
		if nx := cur.children[c]; nx != nil {
			cur = nx
		} else {
			cur = m.root
		}
		if len(cur.outputs) == 0 {
			continue
		}
		if seen == nil {
			seen = make(map[string]struct{})
		}
		for _, out := range cur.outputs {
			if _, ok := seen[out]; !ok {
				seen[out] = struct{}{}
				res = append(res, out)
			}
		}
	}
	return res
}

// MatchesAny reports whether any pattern occurs in text, stopping at the first
// hit. Cheaper than Match when you only need a yes/no answer.
func (m *Matcher) MatchesAny(text string) bool {
	if m.empty {
		return false
	}
	cur := m.root
	for i := 0; i < len(text); i++ {
		c := text[i]
		for cur != m.root && cur.children[c] == nil {
			cur = cur.fail
		}
		if nx := cur.children[c]; nx != nil {
			cur = nx
		} else {
			cur = m.root
		}
		if len(cur.outputs) > 0 {
			return true
		}
	}
	return false
}
