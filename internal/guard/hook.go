package guard

import (
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"time"
)

// BanHook runs an external command whenever an IP is banned or unbanned. Its
// purpose is to push Knight's verdicts DOWN into the kernel firewall: with an
// nftables set (see deploy/nftables.conf.example), a banned IP is dropped for
// every port and protocol -- so even a stealth SYN scan from that IP gets
// nothing back. The literal token {ip} in an argument is replaced with the
// offending address.
//
// Example config:
//
//	"ban_command":   ["nft", "add",    "element", "inet", "knight", "banned", "{ip}"]
//	"unban_command": ["nft", "delete", "element", "inet", "knight", "banned", "{ip}"]
type BanHook struct {
	banCmd   []string
	unbanCmd []string
	log      *slog.Logger
}

// NewBanHook returns a hook; empty commands are simply skipped.
func NewBanHook(banCmd, unbanCmd []string, log *slog.Logger) *BanHook {
	return &BanHook{banCmd: banCmd, unbanCmd: unbanCmd, log: log}
}

// OnBlock is called by the blocklist after a new ban.
func (h *BanHook) OnBlock(ip string) { h.run(h.banCmd, ip) }

// OnUnblock is called after a ban is lifted (manual or expiry).
func (h *BanHook) OnUnblock(ip string) { h.run(h.unbanCmd, ip) }

func (h *BanHook) run(tmpl []string, ip string) {
	if len(tmpl) == 0 || ip == "" {
		return
	}
	args := make([]string, len(tmpl))
	for i, a := range tmpl {
		args[i] = strings.ReplaceAll(a, "{ip}", ip)
	}
	// Run async: firewall latency must never sit on the request path.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			h.log.Error("ban hook failed",
				"cmd", strings.Join(args, " "), "err", err, "output", string(out))
		}
	}()
}
