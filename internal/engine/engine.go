// Package engine is Knight's detection core. It turns a normalized request into
// a verdict using a two-stage pipeline:
//
//  1. Aho-Corasick prefilter: one O(n) scan of the request collects the set of
//     rule keywords present. Rules whose keyword did not appear are skipped
//     entirely -- this is what lets Knight "just observe" cheaply at line rate.
//  2. Confirmation + scoring: surviving candidate rules run their regex against
//     their specific targets. Each firing rule adds its severity to an anomaly
//     score (OWASP CRS style). The request is blocked if any rule's action is
//     "block" or the total score reaches the configured threshold.
package engine

import (
	"knight/internal/ahocorasick"
	"knight/internal/request"
)

// Match records a single rule that fired.
type Match struct {
	RuleID   string
	Name     string
	Severity int
	Tags     []string
}

// Verdict is the result of evaluating one request.
type Verdict struct {
	Block   bool
	Score   int
	Matches []Match
}

// Engine holds the compiled ruleset and the prefilter automaton.
type Engine struct {
	rules        []*Rule
	prefilter    *ahocorasick.Matcher
	keywordRules map[string][]*Rule // keyword -> rules that listed it
	alwaysRun    []*Rule            // keyword-less regex rules (run every time)
	threshold    int
}

// New compiles the rules into an executable engine. threshold is the anomaly
// score at or above which a request is blocked.
func New(rules []*Rule, threshold int) *Engine {
	e := &Engine{
		rules:        rules,
		keywordRules: map[string][]*Rule{},
		threshold:    threshold,
	}
	var patterns []string
	seenPat := map[string]bool{}
	for _, r := range rules {
		if !r.enabled() {
			continue
		}
		if len(r.Keywords) == 0 {
			// No cheap prefilter available; must run on every request.
			e.alwaysRun = append(e.alwaysRun, r)
			continue
		}
		for _, k := range r.Keywords {
			e.keywordRules[k] = append(e.keywordRules[k], r)
			if !seenPat[k] {
				seenPat[k] = true
				patterns = append(patterns, k)
			}
		}
	}
	e.prefilter = ahocorasick.New(patterns)
	return e
}

// Evaluate runs the pipeline against a normalized request.
func (e *Engine) Evaluate(ctx *request.Context) Verdict {
	var v Verdict
	fired := map[string]bool{}

	consider := func(r *Rule) {
		if fired[r.ID] || !r.enabled() {
			return
		}
		if e.ruleMatches(r, ctx) {
			fired[r.ID] = true
			v.Score += r.Severity
			v.Matches = append(v.Matches, Match{
				RuleID: r.ID, Name: r.Name, Severity: r.Severity, Tags: r.Tags,
			})
			if r.Action == "block" {
				v.Block = true
			}
		}
	}

	// Stage 1: prefilter scan -> candidate rules.
	for _, kw := range e.prefilter.Match(ctx.Combined()) {
		for _, r := range e.keywordRules[kw] {
			consider(r)
		}
	}
	// Keyword-less rules always get a look.
	for _, r := range e.alwaysRun {
		consider(r)
	}

	if e.threshold > 0 && v.Score >= e.threshold {
		v.Block = true
	}
	return v
}

// ruleMatches confirms a candidate rule against its declared targets.
func (e *Engine) ruleMatches(r *Rule, ctx *request.Context) bool {
	for _, t := range r.targets() {
		text := ctx.Target(t)
		if text == "" {
			continue
		}
		if r.re != nil {
			if r.re.MatchString(text) {
				return true
			}
			continue
		}
		// Keyword-only rule: a keyword present in this specific target.
		for _, k := range r.Keywords {
			if containsFold(text, k) {
				return true
			}
		}
	}
	return false
}

// containsFold reports whether sub (already lower-cased) is within s (already
// lower-cased). Both come from the normalizer, so a plain substring check is
// enough and avoids allocations.
func containsFold(s, sub string) bool {
	if sub == "" {
		return false
	}
	n := len(s) - len(sub)
	for i := 0; i <= n; i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// RuleCount returns how many enabled rules the engine holds.
func (e *Engine) RuleCount() int {
	n := 0
	for _, r := range e.rules {
		if r.enabled() {
			n++
		}
	}
	return n
}
