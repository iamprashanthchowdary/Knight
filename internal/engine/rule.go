package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Rule is one signature in Knight's ruleset. It is intentionally close in shape
// to an OWASP CRS rule: match some part of the request, contribute a severity
// score, and optionally force an action.
//
// A rule fires when EITHER of these holds for one of its targets:
//   - it has a Regex and the regex matches, or
//   - it has no Regex and one of its Keywords is present.
//
// Keywords double as the Aho-Corasick prefilter: a regex rule only runs its
// (expensive) regex if one of its keywords was seen in the single prefilter
// scan. Give every regex rule at least one cheap literal keyword that MUST be
// present for the regex to match (e.g. "select", "<script", "../").
type Rule struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity int      `json:"severity"`          // anomaly score added when it fires
	Targets  []string `json:"targets"`           // e.g. ["query","body"]; empty = ["any"]
	Keywords []string `json:"keywords"`          // literal prefilter tokens (lower-cased)
	Regex    string   `json:"regex,omitempty"`   // optional RE2 confirmation
	Action   string   `json:"action,omitempty"`  // "block" forces a block regardless of score
	Tags     []string `json:"tags,omitempty"`    // e.g. ["sqli"], informational
	Enabled  *bool    `json:"enabled,omitempty"` // defaults to true

	re *regexp.Regexp
}

func (r *Rule) enabled() bool { return r.Enabled == nil || *r.Enabled }

func (r *Rule) targets() []string {
	if len(r.Targets) == 0 {
		return []string{"any"}
	}
	return r.Targets
}

// compile validates the rule and pre-compiles its regex.
func (r *Rule) compile() error {
	if r.ID == "" {
		return fmt.Errorf("rule missing id")
	}
	if r.Regex == "" && len(r.Keywords) == 0 {
		return fmt.Errorf("rule %s has neither regex nor keywords", r.ID)
	}
	if r.Regex != "" {
		re, err := regexp.Compile(r.Regex) // RE2: linear time, no catastrophic backtracking
		if err != nil {
			return fmt.Errorf("rule %s: bad regex: %w", r.ID, err)
		}
		r.re = re
	}
	// Normalize keywords to lower case to match the normalized request text.
	for i, k := range r.Keywords {
		r.Keywords[i] = strings.ToLower(k)
	}
	if r.Severity <= 0 {
		r.Severity = 5
	}
	return nil
}

// ruleFile is the on-disk JSON container.
type ruleFile struct {
	Rules []*Rule `json:"rules"`
}

// LoadRules reads and compiles a ruleset from a JSON file.
func LoadRules(path string) ([]*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rf ruleFile
	if err := json.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("parse rules %s: %w", path, err)
	}
	out := make([]*Rule, 0, len(rf.Rules))
	seen := map[string]bool{}
	for _, r := range rf.Rules {
		if err := r.compile(); err != nil {
			return nil, err
		}
		if seen[r.ID] {
			return nil, fmt.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		out = append(out, r)
	}
	return out, nil
}
