package alerts

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Notifier delivers an Alert to one channel.
type Notifier interface {
	Notify(a Alert) error
}

// WebhookNotifier POSTs the alert to a fixed URL. Two payload shapes:
//
//   - Google Chat incoming webhooks (chat.googleapis.com) are detected
//     automatically and sent a Chat-native {"text": "..."} message. Chat's API
//     is protobuf-backed and can reject unrecognized top-level JSON fields
//     outright, so Knight's generic Alert shape would not reliably render.
//   - Everything else gets Knight's raw Alert JSON. If Secret is set, the body
//     is HMAC-SHA256 signed and sent as X-Knight-Signature (hex) so the
//     receiver can verify the request came from this agent.
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
	body, sign, err := webhookPayload(w.URL, a)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if sign && w.Secret != "" {
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

// webhookPayload builds the request body for a target URL, and reports
// whether it should be HMAC-signed (skipped for Google Chat: its own key/token
// query params are the auth mechanism, and signing a Chat-format body serves
// no purpose since Chat itself never checks it).
func webhookPayload(rawURL string, a Alert) (body []byte, sign bool, err error) {
	if isGoogleChatWebhook(rawURL) {
		body, err = json.Marshal(struct {
			Text string `json:"text"`
		}{Text: chatMessageText(a)})
		return body, false, err
	}
	body, err = json.Marshal(a)
	return body, true, err
}

func isGoogleChatWebhook(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return u.Hostname() == "chat.googleapis.com"
}

// chatMessageText renders an Alert as a Google Chat message using Chat's
// lightweight markup (*bold*).
func chatMessageText(a Alert) string {
	var b strings.Builder
	b.WriteString("🚨 *Knight alert*: ")
	b.WriteString(a.Message)
	if a.Site != "" {
		fmt.Fprintf(&b, "\n*Site:* %s", a.Site)
	}
	if a.Metric != "" {
		fmt.Fprintf(&b, "\n*Metric:* %s", a.Metric)
	}
	if a.Window != "" {
		fmt.Fprintf(&b, "\n*Window:* %s", a.Window)
	}
	fmt.Fprintf(&b, "\n*Time:* %s", a.Time.Format(time.RFC3339))
	return b.String()
}
