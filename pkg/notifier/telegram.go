package notifier

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	tgbotapi "github.com/matterbridge/telegram-bot-api/v6"
	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
)

// TelegramNotifier sends notifications via Telegram forum topics
type TelegramNotifier struct {
	botToken   string
	groupID    int64
	enabled    bool
	bot        *tgbotapi.BotAPI
	topicCache map[string]int // app name -> topic ID
	cacheMu    sync.RWMutex
}

// NewTelegramNotifier creates a new TelegramNotifier
func NewTelegramNotifier(botToken string, groupID int64, enabled bool) (*TelegramNotifier, error) {
	notifier := &TelegramNotifier{
		botToken:   botToken,
		groupID:    groupID,
		enabled:    enabled && botToken != "" && groupID != 0,
		topicCache: make(map[string]int),
	}

	if notifier.enabled {
		bot, err := tgbotapi.NewBotAPI(botToken)
		if err != nil {
			return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
		}
		notifier.bot = bot
		zap.S().Infof("Telegram bot initialized: %s", bot.Self.UserName)
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

// Send implements Notifier interface but is not used for forum topics.
// Use SendToTopic instead for forum-based notifications.
func (n *TelegramNotifier) Send(ctx context.Context, report *models.Report, recipients []string) error {
	return fmt.Errorf("telegram notifier uses forum topics; use SendToTopic instead")
}

// SendToTopic sends a Telegram notification to an app's forum topic.
// If existingTopicID is 0, a new topic will be created.
// Returns the topic ID used (existing or newly created) so it can be persisted.
func (n *TelegramNotifier) SendToTopic(ctx context.Context, report *models.Report, appName string, existingTopicID int) (int, error) {
	if !n.enabled || n.bot == nil {
		return 0, fmt.Errorf("telegram notifier is not enabled")
	}

	if appName == "" {
		return 0, fmt.Errorf("app name is required for forum topic")
	}

	// Get or create the forum topic for this app
	topicID, err := n.getOrCreateTopic(appName, existingTopicID)
	if err != nil {
		return 0, fmt.Errorf("failed to get/create topic for app %s: %w", appName, err)
	}

	message := n.buildMessage(report)

	msg := tgbotapi.NewMessage(n.groupID, message)
	msg.MessageThreadID = topicID
	msg.ParseMode = "Markdown"

	sentMsg, err := n.bot.Send(msg)
	if err != nil {
		zap.S().Errorf("Failed to send Telegram message with Markdown to topic topic_id=%d app=%s error=%v",
			topicID,
			appName,
			err,
		)
		// Try without markdown if parsing fails
		msg.ParseMode = ""
		msg.Text = n.buildPlainMessage(report)
		sentMsg, err = n.bot.Send(msg)
		if err != nil {
			return topicID, fmt.Errorf("failed to send to topic %d: %w", topicID, err)
		}
	}

	// Check if message went to the correct topic (not General)
	// If topic was deleted, Telegram sends to General (thread_id=0) instead of the specified topic
	if existingTopicID > 0 && sentMsg.MessageThreadID != topicID {
		zap.S().Warnf("Topic %d appears to be deleted (message went to thread %d), creating new topic for app=%s",
			topicID,
			sentMsg.MessageThreadID,
			appName,
		)

		// Clear cache and create a new topic
		n.invalidateTopicCache(appName)

		newTopicID, err := n.createForumTopic(appName)
		if err != nil {
			zap.S().Errorf("Failed to create replacement topic for app=%s: %v", appName, err)
			return 0, nil
		}

		// Cache the new topic
		n.cacheMu.Lock()
		n.topicCache[appName] = newTopicID
		n.cacheMu.Unlock()

		// Resend to the new topic
		msg.MessageThreadID = newTopicID
		msg.ParseMode = "Markdown"
		msg.Text = message
		if _, err = n.bot.Send(msg); err != nil {
			msg.ParseMode = ""
			msg.Text = n.buildPlainMessage(report)
			n.bot.Send(msg)
		}

		zap.S().Infof("Created replacement topic for app=%s new_topic_id=%d", appName, newTopicID)
		topicID = newTopicID
	}

	zap.S().Infof("Telegram notification sent to topic topic_id=%d app=%s", topicID, appName)
	return topicID, nil
}

// getOrCreateTopic gets the topic ID from database/cache or creates a new topic for the app.
// If existingTopicID > 0, it uses that (from database). Otherwise checks cache, then creates new.
func (n *TelegramNotifier) getOrCreateTopic(appName string, existingTopicID int) (int, error) {
	// If we have an existing topic ID from the database, use it and cache it
	if existingTopicID > 0 {
		zap.S().Debugf("Using existing topic id %d for app %s (from database)", existingTopicID, appName)
		n.cacheMu.Lock()
		n.topicCache[appName] = existingTopicID
		n.cacheMu.Unlock()
		return existingTopicID, nil
	}

	// Check cache
	n.cacheMu.RLock()
	if topicID, ok := n.topicCache[appName]; ok {
		zap.S().Debugf("Using cached topic id %d for app %s", topicID, appName)
		n.cacheMu.RUnlock()
		return topicID, nil
	}
	n.cacheMu.RUnlock()

	// Create new topic
	n.cacheMu.Lock()
	defer n.cacheMu.Unlock()

	// Double-check after acquiring write lock
	if topicID, ok := n.topicCache[appName]; ok {
		return topicID, nil
	}

	topicID, err := n.createForumTopic(appName)
	if err != nil {
		return 0, err
	}

	n.topicCache[appName] = topicID
	zap.S().Infof("Created new forum topic for app=%s topic_id=%d", appName, topicID)

	return topicID, nil
}

// ForumTopicResponse represents the Telegram API response for forum topic creation
type ForumTopicResponse struct {
	MessageThreadID int    `json:"message_thread_id"`
	Name            string `json:"name"`
	IconColor       int    `json:"icon_color"`
}

// createForumTopic creates a new forum topic for the app
func (n *TelegramNotifier) createForumTopic(appName string) (int, error) {
	// Create the topic name with a security icon
	topicName := fmt.Sprintf("Security: %s", appName)

	config := tgbotapi.CreateForumTopicConfig{
		BaseForum: tgbotapi.BaseForum{
			ChatID: n.groupID,
		},
		Name: topicName,
	}

	resp, err := n.bot.Request(config)
	if err != nil {
		// Check if error indicates topic might already exist or permission issue
		errStr := err.Error()
		if strings.Contains(errStr, "TOPIC_NOT_MODIFIED") {
			return 0, fmt.Errorf("topic creation conflict: %w", err)
		}
		if strings.Contains(errStr, "not enough rights") || strings.Contains(errStr, "CHAT_ADMIN_REQUIRED") {
			return 0, fmt.Errorf("bot lacks 'Manage Topics' permission in the forum group: %w", err)
		}
		if strings.Contains(errStr, "PEER_ID_INVALID") || strings.Contains(errStr, "chat not found") {
			return 0, fmt.Errorf("invalid group ID or bot is not a member of the group: %w", err)
		}
		if strings.Contains(errStr, "CHAT_NOT_FORUM") || strings.Contains(errStr, "not a forum") {
			return 0, fmt.Errorf("the group is not a forum (topics are not enabled): %w", err)
		}
		return 0, fmt.Errorf("failed to create forum topic: %w", err)
	}

	// Parse the response to get the topic ID
	data, err := resp.Result.MarshalJSON()
	if err != nil {
		return 0, fmt.Errorf("failed to marshal forum topic response: %w", err)
	}

	zap.S().Debugf("Forum topic raw response: %s", string(data))

	var topicResult ForumTopicResponse
	if err := json.Unmarshal(data, &topicResult); err != nil {
		return 0, fmt.Errorf("failed to parse forum topic response: %w", err)
	}

	if topicResult.MessageThreadID <= 0 {
		return 0, fmt.Errorf("invalid message_thread_id in response: %d", topicResult.MessageThreadID)
	}

	return topicResult.MessageThreadID, nil
}

// buildMessage creates the Telegram message with Markdown formatting
func (n *TelegramNotifier) buildMessage(report *models.Report) string {
	var sb strings.Builder

	// Header with emoji based on severity
	emoji := n.getSeverityEmoji(report)
	sb.WriteString(fmt.Sprintf("%s *Security Alert: %s*\n\n", emoji, report.AppName))

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

// SendCombinedToTopic sends a combined Telegram notification for multiple audit results.
// If existingTopicID is 0, a new topic will be created.
// Returns the topic ID used (existing or newly created) so it can be persisted.
func (n *TelegramNotifier) SendCombinedToTopic(ctx context.Context, combinedReport *models.CombinedAppReport, appName string, existingTopicID int) (int, error) {
	if !n.enabled || n.bot == nil {
		return 0, fmt.Errorf("telegram notifier is not enabled")
	}

	if appName == "" {
		return 0, fmt.Errorf("app name is required for forum topic")
	}

	// Get or create the forum topic for this app
	topicID, err := n.getOrCreateTopic(appName, existingTopicID)
	if err != nil {
		return 0, fmt.Errorf("failed to get/create topic for app %s: %w", appName, err)
	}

	// Build combined message
	message := n.buildCombinedMessage(combinedReport)
	plainMessage := n.buildCombinedPlainMessage(combinedReport)

	// Send message with attachments
	sentThreadID, err := n.sendMessageWithAttachments(topicID, message, plainMessage, combinedReport.ReportFiles)
	if err != nil {
		return topicID, fmt.Errorf("failed to send combined message to topic %d: %w", topicID, err)
	}

	// Check if message went to the correct topic (not General)
	// If topic was deleted, Telegram sends to General (thread_id=0) instead of the specified topic
	if existingTopicID > 0 && sentThreadID != topicID {
		zap.S().Warnf("Topic %d appears to be deleted (message went to thread %d), creating new topic for app=%s",
			topicID,
			sentThreadID,
			appName,
		)

		// Clear cache and create a new topic
		n.invalidateTopicCache(appName)

		newTopicID, err := n.createForumTopic(appName)
		if err != nil {
			zap.S().Errorf("Failed to create replacement topic for app=%s: %v", appName, err)
			// Return 0 to force database update (clear the invalid topic ID)
			return 0, nil
		}

		// Cache the new topic
		n.cacheMu.Lock()
		n.topicCache[appName] = newTopicID
		n.cacheMu.Unlock()

		// Resend to the new topic
		_, err = n.sendMessageWithAttachments(newTopicID, message, plainMessage, combinedReport.ReportFiles)
		if err != nil {
			zap.S().Warnf("Failed to resend to new topic: %v", err)
		}

		zap.S().Infof("Created replacement topic for app=%s new_topic_id=%d", appName, newTopicID)
		topicID = newTopicID
	}

	zap.S().Infof("Combined Telegram notification sent to topic topic_id=%d app=%s auditors=%d files=%d",
		topicID,
		appName,
		len(combinedReport.Reports),
		len(combinedReport.ReportFiles),
	)

	return topicID, nil
}

// sendMessageWithAttachments sends a message with file attachments as a single media group.
// Returns the thread ID of the sent message.
func (n *TelegramNotifier) sendMessageWithAttachments(topicID int, message, plainMessage string, filePaths []string) (int, error) {
	// If no files, send as regular text message
	if len(filePaths) == 0 {
		msg := tgbotapi.NewMessage(n.groupID, message)
		msg.MessageThreadID = topicID
		msg.ParseMode = "Markdown"

		sentMsg, err := n.bot.Send(msg)
		if err != nil {
			// Try without markdown
			msg.ParseMode = ""
			msg.Text = plainMessage
			sentMsg, err = n.bot.Send(msg)
			if err != nil {
				return 0, err
			}
		}
		return sentMsg.MessageThreadID, nil
	}

	// Send files as media group with caption on first file
	mediaGroup := make([]interface{}, len(filePaths))
	for i, filePath := range filePaths {
		doc := tgbotapi.NewInputMediaDocument(tgbotapi.FilePath(filePath))
		if i == 0 {
			// First document gets the caption
			doc.Caption = message
			doc.ParseMode = "Markdown"
		}
		mediaGroup[i] = doc
	}

	config := tgbotapi.NewMediaGroup(n.groupID, mediaGroup)
	config.MessageThreadID = topicID

	sentMsgs, err := n.bot.SendMediaGroup(config)
	if err != nil {
		zap.S().Warnf("Failed to send media group with Markdown: %v, retrying with plain text", err)

		// Retry without markdown
		for i := range mediaGroup {
			if doc, ok := mediaGroup[i].(tgbotapi.InputMediaDocument); ok {
				if i == 0 {
					doc.Caption = plainMessage
					doc.ParseMode = ""
				}
				mediaGroup[i] = doc
			}
		}
		config = tgbotapi.NewMediaGroup(n.groupID, mediaGroup)
		config.MessageThreadID = topicID

		sentMsgs, err = n.bot.SendMediaGroup(config)
		if err != nil {
			return 0, fmt.Errorf("failed to send media group: %w", err)
		}
	}

	// Return the thread ID from the first sent message
	if len(sentMsgs) > 0 {
		return sentMsgs[0].MessageThreadID, nil
	}

	return topicID, nil
}

// invalidateTopicCache removes a topic from the cache
func (n *TelegramNotifier) invalidateTopicCache(appName string) {
	n.cacheMu.Lock()
	defer n.cacheMu.Unlock()
	delete(n.topicCache, appName)
}

// buildCombinedMessage creates the combined Telegram message with Markdown formatting
func (n *TelegramNotifier) buildCombinedMessage(combinedReport *models.CombinedAppReport) string {
	var sb strings.Builder

	// Calculate combined summary
	summary := combinedReport.GetCombinedSummary()

	// Header with emoji based on severity
	emoji := n.getCombinedSeverityEmoji(summary)
	sb.WriteString(fmt.Sprintf("%s *Security Alert: %s*\n\n", emoji, combinedReport.AppName))

	// Combined Summary
	sb.WriteString("*Combined Vulnerabilities:*\n")
	if summary.Critical > 0 {
		sb.WriteString(fmt.Sprintf("  - Critical: %d\n", summary.Critical))
	}
	if summary.High > 0 {
		sb.WriteString(fmt.Sprintf("  - High: %d\n", summary.High))
	}
	if summary.Moderate > 0 {
		sb.WriteString(fmt.Sprintf("  - Moderate: %d\n", summary.Moderate))
	}
	if summary.Low > 0 {
		sb.WriteString(fmt.Sprintf("  - Low: %d\n", summary.Low))
	}
	sb.WriteString(fmt.Sprintf("  - *Total: %d*\n\n", summary.Total))

	// Per-auditor breakdown
	sb.WriteString("*Breakdown by Package Manager:*\n")
	for _, report := range combinedReport.Reports {
		if report.AuditResult.TotalVulnerabilities > 0 {
			sb.WriteString(fmt.Sprintf("  - %s: %d vulnerabilities\n",
				strings.ToUpper(report.AuditorType),
				report.AuditResult.TotalVulnerabilities,
			))
		}
	}
	sb.WriteString("\n")

	// Top vulnerabilities across all auditors (limit to 5)
	allVulns := n.collectTopVulnerabilities(combinedReport, 5)
	if len(allVulns) > 0 {
		sb.WriteString("*Top Issues:*\n")
		for i, v := range allVulns {
			sb.WriteString(fmt.Sprintf("%d. %s (%s)\n",
				i+1,
				escapeMarkdown(v.PackageName),
				strings.ToUpper(v.Severity),
			))
		}

		// Count total remaining
		totalVulns := 0
		for _, r := range combinedReport.Reports {
			totalVulns += len(r.Vulnerabilities)
		}
		if totalVulns > 5 {
			sb.WriteString(fmt.Sprintf("... and %d more\n", totalVulns-5))
		}
		sb.WriteString("\n")
	}

	// AI Summary if available (from any report)
	for _, report := range combinedReport.Reports {
		if report.AIAnalysis != nil && report.AIAnalysis.Summary != "" {
			sb.WriteString("*AI Summary:*\n")
			sb.WriteString(escapeMarkdown(report.AIAnalysis.Summary))
			sb.WriteString("\n\n")
			break // Only include one AI summary
		}
	}

	// Quick fix suggestions
	var fixCommands []string
	for _, report := range combinedReport.Reports {
		if report.AuditorType == "npm" {
			fixCommands = append(fixCommands, "`npm audit fix`")
		} else if report.AuditorType == "composer" {
			fixCommands = append(fixCommands, "`composer update`")
		}
	}
	if len(fixCommands) > 0 {
		sb.WriteString(fmt.Sprintf("_Run %s to fix issues_", strings.Join(fixCommands, " and ")))
	}

	return sb.String()
}

// buildCombinedPlainMessage creates a plain text combined message (fallback)
func (n *TelegramNotifier) buildCombinedPlainMessage(combinedReport *models.CombinedAppReport) string {
	var sb strings.Builder

	summary := combinedReport.GetCombinedSummary()
	emoji := n.getCombinedSeverityEmoji(summary)

	sb.WriteString(fmt.Sprintf("%s Security Alert: %s\n\n", emoji, combinedReport.AppName))

	sb.WriteString("Combined Vulnerabilities:\n")
	sb.WriteString(fmt.Sprintf("  - Critical: %d\n", summary.Critical))
	sb.WriteString(fmt.Sprintf("  - High: %d\n", summary.High))
	sb.WriteString(fmt.Sprintf("  - Moderate: %d\n", summary.Moderate))
	sb.WriteString(fmt.Sprintf("  - Low: %d\n", summary.Low))
	sb.WriteString(fmt.Sprintf("  - Total: %d\n\n", summary.Total))

	sb.WriteString("Breakdown by Package Manager:\n")
	for _, report := range combinedReport.Reports {
		if report.AuditResult.TotalVulnerabilities > 0 {
			sb.WriteString(fmt.Sprintf("  - %s: %d vulnerabilities\n",
				strings.ToUpper(report.AuditorType),
				report.AuditResult.TotalVulnerabilities,
			))
		}
	}

	allVulns := n.collectTopVulnerabilities(combinedReport, 5)
	if len(allVulns) > 0 {
		sb.WriteString("\nTop Issues:\n")
		for i, v := range allVulns {
			sb.WriteString(fmt.Sprintf("%d. %s (%s)\n",
				i+1,
				v.PackageName,
				strings.ToUpper(v.Severity),
			))
		}
	}

	return sb.String()
}

// collectTopVulnerabilities collects top N vulnerabilities sorted by severity
func (n *TelegramNotifier) collectTopVulnerabilities(combinedReport *models.CombinedAppReport, limit int) []models.Vulnerability {
	var allVulns []models.Vulnerability

	for _, report := range combinedReport.Reports {
		allVulns = append(allVulns, report.Vulnerabilities...)
	}

	// Sort by severity (critical first)
	for i := 0; i < len(allVulns)-1; i++ {
		for j := i + 1; j < len(allVulns); j++ {
			if models.SeverityOrder[allVulns[j].Severity] > models.SeverityOrder[allVulns[i].Severity] {
				allVulns[i], allVulns[j] = allVulns[j], allVulns[i]
			}
		}
	}

	if len(allVulns) > limit {
		return allVulns[:limit]
	}
	return allVulns
}

// getCombinedSeverityEmoji returns an emoji based on the combined severity
func (n *TelegramNotifier) getCombinedSeverityEmoji(summary models.Summary) string {
	if summary.Critical > 0 {
		return "\xF0\x9F\x9A\xA8" // Red siren
	}
	if summary.High > 0 {
		return "\xE2\x9A\xA0\xEF\xB8\x8F" // Warning
	}
	if summary.Moderate > 0 {
		return "\xF0\x9F\x9F\xA1" // Yellow circle
	}
	return "\xF0\x9F\x9F\xA2" // Green circle
}
