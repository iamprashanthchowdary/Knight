package ahocorasick

import (
	"sort"
	"testing"
)

func TestMatchFindsAllOverlapping(t *testing.T) {
	m := New([]string{"he", "she", "his", "hers"})
	got := m.Match("ushers")
	sort.Strings(got)
	want := []string{"he", "hers", "she"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestMatchesAny(t *testing.T) {
	m := New([]string{"union", "select"})
	if !m.MatchesAny("id=1 union all select 2") {
		t.Fatal("expected a match")
	}
	if m.MatchesAny("perfectly normal request") {
		t.Fatal("unexpected match")
	}
}

func TestEmptyMatcher(t *testing.T) {
	m := New(nil)
	if m.MatchesAny("anything") || m.Match("anything") != nil {
		t.Fatal("empty matcher should never match")
	}
}
