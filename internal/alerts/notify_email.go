package alerts

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailNotifier sends alerts via an SMTP relay using only the Go standard
// library (net/smtp + crypto/tls) -- no third-party mail library, matching
// Knight's zero-dependency, single-binary build. It supports implicit TLS on
// port 465 and STARTTLS on other ports (falling back to plain if the server
// offers no STARTTLS extension, so a local unencrypted relay still works).
type EmailNotifier struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
}

// NewEmailNotifier builds an EmailNotifier.
func NewEmailNotifier(host string, port int, username, password, from string, to []string) *EmailNotifier {
	return &EmailNotifier{Host: host, Port: port, Username: username, Password: password, From: from, To: to}
}

// Notify sends the alert as a plain-text email.
func (e *EmailNotifier) Notify(a Alert) error {
	subject := "[Knight] " + a.Message
	body := fmt.Sprintf(
		"%s\n\nMetric:    %s\nValue:     %.4f\nThreshold: %.4f\nWindow:    %s\nSite:      %s\nTime:      %s\n",
		a.Message, a.Metric, a.Value, a.Threshold, orDefault(a.Window, "-"), orDefault(a.Site, "(all sites)"),
		a.Time.Format(time.RFC3339),
	)
	msg := buildMIME(e.From, e.To, subject, body)
	return e.send(msg)
}

func (e *EmailNotifier) send(msg string) error {
	addr := fmt.Sprintf("%s:%d", e.Host, e.Port)

	var client *smtp.Client
	if e.Port == 465 {
		conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: e.Host})
		if err != nil {
			return fmt.Errorf("smtp dial (implicit tls): %w", err)
		}
		client, err = smtp.NewClient(conn, e.Host)
		if err != nil {
			return err
		}
	} else {
		conn, err := net.DialTimeout("tcp", addr, 8*time.Second)
		if err != nil {
			return fmt.Errorf("smtp dial: %w", err)
		}
		client, err = smtp.NewClient(conn, e.Host)
		if err != nil {
			return err
		}
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: e.Host}); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		}
	}
	defer client.Close()

	if e.Username != "" {
		if ok, _ := client.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", e.Username, e.Password, e.Host)
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := client.Mail(e.From); err != nil {
		return err
	}
	for _, rcpt := range e.To {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("rcpt %s: %w", rcpt, err)
		}
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func buildMIME(from string, to []string, subject, body string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
