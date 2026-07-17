package alerts

import (
	"encoding/json"
	"testing"
	"time"
)

func TestWebhookPayloadGoogleChat(t *testing.T) {
	a := Alert{
		ID: "high-5xx", Kind: "threshold", Site: "swiftflow", Metric: "status_count",
		Value: 12, Threshold: 5, Window: "2m", Message: "12 matching requests in 2m",
		Time: time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC),
	}
	url := "https://chat.googleapis.com/v1/spaces/AAA/messages?key=K&token=T"

	body, sign, err := webhookPayload(url, a)
	if err != nil {
		t.Fatal(err)
	}
	if sign {
		t.Error("expected Google Chat payloads to not be HMAC-signed")
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Fatalf("expected exactly one top-level field (text), got %d: %v", len(decoded), decoded)
	}
	text, ok := decoded["text"].(string)
	if !ok || text == "" {
		t.Fatalf("expected a non-empty top-level 'text' field, got %v", decoded)
	}
	if !contains(text, a.Message) || !contains(text, a.Site) {
		t.Errorf("chat text missing expected content: %q", text)
	}
}

func TestWebhookPayloadGeneric(t *testing.T) {
	a := Alert{ID: "high-5xx", Kind: "threshold", Message: "test", Time: time.Now()}
	url := "https://example.com/hook"

	body, sign, err := webhookPayload(url, a)
	if err != nil {
		t.Fatal(err)
	}
	if !sign {
		t.Error("expected non-Chat webhooks to still be HMAC-signable")
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	// Generic receivers get the full Alert shape, not just "text".
	if _, ok := decoded["id"]; !ok {
		t.Error("expected generic payload to retain the full Alert shape (id field)")
	}
}

func TestIsGoogleChatWebhook(t *testing.T) {
	cases := map[string]bool{
		"https://chat.googleapis.com/v1/spaces/X/messages?key=K&token=T": true,
		"https://example.com/webhook":                                    false,
		"not a url at all":                                               false,
		"":                                                               false,
	}
	for url, want := range cases {
		if got := isGoogleChatWebhook(url); got != want {
			t.Errorf("isGoogleChatWebhook(%q) = %v, want %v", url, got, want)
		}
	}
}

func contains(s, substr string) bool {
	return substr == "" || len(s) >= len(substr) && (func() bool {
		for i := 0; i+len(substr) <= len(s); i++ {
			if s[i:i+len(substr)] == substr {
				return true
			}
		}
		return false
	})()
}
