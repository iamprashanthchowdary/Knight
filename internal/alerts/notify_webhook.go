package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier delivers an Alert to one channel.
type Notifier interface {
	Notify(a Alert) error
}

// WebhookNotifier POSTs the alert as JSON to a fixed URL. If Secret is set, the
// body is HMAC-SHA256 signed and sent as the X-Knight-Signature header (hex),
// so the receiver can verify the request actually came from this agent and
// wasn't spoofed or replayed from a tampered body.
type WebhookNotifier struct {
	URL    string
	Secret string
	Client *http.Client
}

// NewWebhookNotifier builds a WebhookNotifier with a sane request timeout.
func NewWebhookNotifier(url, secret string) *WebhookNotifier {
	return &WebhookNotifier{URL: url, Secret: secret, Client: &http.Client{Timeout: 5 * time.Second}}
}

// Notify sends the alert. A non-2xx response is treated as failure.
func (w *WebhookNotifier) Notify(a Alert) error {
	body, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if w.Secret != "" {
		mac := hmac.New(sha256.New, []byte(w.Secret))
		mac.Write(body)
		req.Header.Set("X-Knight-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := w.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned %s", resp.Status)
	}
	return nil
}
