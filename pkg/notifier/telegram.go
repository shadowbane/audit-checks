package notifier

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
)

// TelegramNotifier sends notifications via Telegram
type TelegramNotifier struct {
	botToken string
	enabled  bool
	bot      *tgbotapi.BotAPI
}

// NewTelegramNotifier creates a new TelegramNotifier
func NewTelegramNotifier(botToken string, enabled bool) (*TelegramNotifier, error) {
	notifier := &TelegramNotifier{
		botToken: botToken,
		enabled:  enabled && botToken != "",
	}

	if notifier.enabled {
		bot, err := tgbotapi.NewBotAPI(botToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
		}
		notifier.bot = bot
	}

	return notifier, nil
}

// Name returns "telegram"
func (n *TelegramNotifier) Name() string {
	return "telegram"
}

// Enabled returns true if the notifier is configured
func (n *TelegramNotifier) Enabled() bool {
	return n.enabled
}

// Send sends a Telegram notification
func (n *TelegramNotifier) Send(ctx context.Context, report *models.Report, recipients []string) error {
	if !n.enabled || n.bot == nil {
		return fmt.Errorf("telegram notifier is not enabled")
	}

	if len(recipients) == 0 {
		return nil
	}

	message := n.buildMessage(report)

	for _, recipient := range recipients {
		chatID, err := strconv.ParseInt(recipient, 10, 64)
		if err != nil {
			zap.S().Errorf("Invalid Telegram chat ID chat_id=%s error=%v",
				recipient,
				err,
			)
			continue
		}

		msg := tgbotapi.NewMessage(chatID, message)
		msg.ParseMode = "Markdown"

		_, err = n.bot.Send(msg)
		if err != nil {
			zap.S().Errorf("Failed to send Telegram message chat_id=%d error=%v",
				chatID,
				err,
			)
			// Try without markdown if parsing fails
			msg.ParseMode = ""
			msg.Text = n.buildPlainMessage(report)
			if _, err = n.bot.Send(msg); err != nil {
				return fmt.Errorf("failed to send to chat %d: %w", chatID, err)
			}
		}
	}

	return nil
}

// buildMessage creates the Telegram message with Markdown formatting
func (n *TelegramNotifier) buildMessage(report *models.Report) string {
	var sb strings.Builder

	// Header with emoji based on severity
	emoji := n.getSeverityEmoji(report)
	sb.WriteString(fmt.Sprintf("%s *Security Alert: %s*\n\n", emoji, escapeMarkdown(report.AppName)))

	// Summary
	sb.WriteString("*Vulnerabilities Found:*\n")
	if report.AuditResult.CriticalCount > 0 {
		sb.WriteString(fmt.Sprintf("  - Critical: %d\n", report.AuditResult.CriticalCount))
	}
	if report.AuditResult.HighCount > 0 {
		sb.WriteString(fmt.Sprintf("  - High: %d\n", report.AuditResult.HighCount))
	}
	if report.AuditResult.ModerateCount > 0 {
		sb.WriteString(fmt.Sprintf("  - Moderate: %d\n", report.AuditResult.ModerateCount))
	}
	if report.AuditResult.LowCount > 0 {
		sb.WriteString(fmt.Sprintf("  - Low: %d\n", report.AuditResult.LowCount))
	}
	sb.WriteString(fmt.Sprintf("  - *Total: %d*\n\n", report.AuditResult.TotalVulnerabilities))

	// Top vulnerabilities (limit to 5)
	if len(report.Vulnerabilities) > 0 {
		sb.WriteString("*Top Issues:*\n")
		limit := 5
		if len(report.Vulnerabilities) < limit {
			limit = len(report.Vulnerabilities)
		}
		for i := 0; i < limit; i++ {
			v := report.Vulnerabilities[i]
			sb.WriteString(fmt.Sprintf("%d. %s (%s)\n",
				i+1,
				escapeMarkdown(v.PackageName),
				strings.ToUpper(v.Severity),
			))
		}
		if len(report.Vulnerabilities) > 5 {
			sb.WriteString(fmt.Sprintf("... and %d more\n", len(report.Vulnerabilities)-5))
		}
		sb.WriteString("\n")
	}

	// AI Summary if available
	if report.AIAnalysis != nil && report.AIAnalysis.Summary != "" {
		sb.WriteString("*AI Summary:*\n")
		sb.WriteString(escapeMarkdown(report.AIAnalysis.Summary))
		sb.WriteString("\n\n")
	}

	// Quick fix suggestion
	if report.AuditorType == "npm" {
		sb.WriteString("_Run `npm audit fix` to automatically fix issues_\n")
	} else if report.AuditorType == "composer" {
		sb.WriteString("_Run `composer update` to update packages_\n")
	}

	return sb.String()
}

// buildPlainMessage creates a plain text message (fallback)
func (n *TelegramNotifier) buildPlainMessage(report *models.Report) string {
	var sb strings.Builder

	emoji := n.getSeverityEmoji(report)
	sb.WriteString(fmt.Sprintf("%s Security Alert: %s\n\n", emoji, report.AppName))

	sb.WriteString("Vulnerabilities Found:\n")
	sb.WriteString(fmt.Sprintf("  - Critical: %d\n", report.AuditResult.CriticalCount))
	sb.WriteString(fmt.Sprintf("  - High: %d\n", report.AuditResult.HighCount))
	sb.WriteString(fmt.Sprintf("  - Moderate: %d\n", report.AuditResult.ModerateCount))
	sb.WriteString(fmt.Sprintf("  - Low: %d\n", report.AuditResult.LowCount))
	sb.WriteString(fmt.Sprintf("  - Total: %d\n\n", report.AuditResult.TotalVulnerabilities))

	if len(report.Vulnerabilities) > 0 {
		sb.WriteString("Top Issues:\n")
		limit := 5
		if len(report.Vulnerabilities) < limit {
			limit = len(report.Vulnerabilities)
		}
		for i := 0; i < limit; i++ {
			v := report.Vulnerabilities[i]
			sb.WriteString(fmt.Sprintf("%d. %s (%s)\n",
				i+1,
				v.PackageName,
				strings.ToUpper(v.Severity),
			))
		}
	}

	return sb.String()
}

// getSeverityEmoji returns an emoji based on the highest severity
func (n *TelegramNotifier) getSeverityEmoji(report *models.Report) string {
	if report.AuditResult.CriticalCount > 0 {
		return "\xF0\x9F\x9A\xA8" // Red siren
	}
	if report.AuditResult.HighCount > 0 {
		return "\xE2\x9A\xA0\xEF\xB8\x8F" // Warning
	}
	if report.AuditResult.ModerateCount > 0 {
		return "\xF0\x9F\x9F\xA1" // Yellow circle
	}
	return "\xF0\x9F\x9F\xA2" // Green circle
}

// escapeMarkdown escapes special Markdown characters
func escapeMarkdown(s string) string {
	replacer := strings.NewReplacer(
		"_", "\\_",
		"*", "\\*",
		"[", "\\[",
		"]", "\\]",
		"(", "\\(",
		")", "\\)",
		"~", "\\~",
		"`", "\\`",
		">", "\\>",
		"#", "\\#",
		"+", "\\+",
		"-", "\\-",
		"=", "\\=",
		"|", "\\|",
		"{", "\\{",
		"}", "\\}",
		".", "\\.",
		"!", "\\!",
	)
	return replacer.Replace(s)
}
