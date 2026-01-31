package notifier

import (
	"context"
	"fmt"
	"sync"

	"github.com/shadowbane/audit-checks/pkg/models"
	"go.uber.org/zap"
)

// Notifier defines the interface for notification senders
type Notifier interface {
	// Name returns the notifier name (e.g., "email", "telegram")
	Name() string

	// Enabled returns true if the notifier is configured and enabled
	Enabled() bool

	// Send sends a notification to the specified recipients
	Send(ctx context.Context, report *models.Report, recipients []string) error
}

// Manager manages notification sending
type Manager struct {
	notifiers map[string]Notifier
	dryRun    bool
	mu        sync.RWMutex
}

// NotificationResult contains the result of sending notifications
type NotificationResult struct {
	TelegramTopicID int // The topic ID used/created (0 if not applicable)
}

// NewManager creates a new notification manager
func NewManager(dryRun bool) *Manager {
	return &Manager{
		notifiers: make(map[string]Notifier),
		dryRun:    dryRun,
	}
}

// Register adds a notifier to the manager
func (m *Manager) Register(n Notifier) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.notifiers[n.Name()] = n
}

// Get returns a notifier by name
func (m *Manager) Get(name string) (Notifier, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	n, ok := m.notifiers[name]
	return n, ok
}

// NotifyAll sends notifications using all configured notifiers.
// Returns NotificationResult with any created/used IDs that should be persisted.
func (m *Manager) NotifyAll(ctx context.Context, report *models.Report, config models.NotificationConfig) (*NotificationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	result := &NotificationResult{}

	// Send email notifications
	if len(config.Email) > 0 {
		if emailNotifier, ok := m.notifiers["email"]; ok && emailNotifier.Enabled() {
			if err := m.send(ctx, emailNotifier, report, config.Email); err != nil {
				errs = append(errs, fmt.Errorf("email: %w", err))
			}
		}
	}

	// Send Telegram notifications
	if config.TelegramEnabled {
		if tg, ok := m.notifiers["telegram"].(*TelegramNotifier); ok && tg.Enabled() {
			topicID, err := m.sendTelegram(ctx, tg, report, config.AppName, config.TelegramTopicID)
			if err != nil {
				errs = append(errs, fmt.Errorf("telegram: %w", err))
			}
			result.TelegramTopicID = topicID
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("notification errors: %v", errs)
	}

	return result, nil
}

// send sends a notification, respecting dry-run mode
func (m *Manager) send(ctx context.Context, notifier Notifier, report *models.Report, recipients []string) error {
	if m.dryRun {
		zap.S().Infof("DRY RUN: Would send notification notifier=%s app=%s recipients=%v",
			notifier.Name(),
			report.AppName,
			recipients,
		)
		return nil
	}

	zap.S().Infof("Sending notification notifier=%s app=%s recipients=%d",
		notifier.Name(),
		report.AppName,
		len(recipients),
	)

	if err := notifier.Send(ctx, report, recipients); err != nil {
		zap.S().Errorf("Failed to send notification notifier=%s app=%s error=%v",
			notifier.Name(),
			report.AppName,
			err,
		)
		return err
	}

	zap.S().Infof("Notification sent successfully notifier=%s app=%s",
		notifier.Name(),
		report.AppName,
	)

	return nil
}

// sendTelegram sends a Telegram notification to an app's forum topic.
// Returns the topic ID used (existing or newly created).
func (m *Manager) sendTelegram(ctx context.Context, tg *TelegramNotifier, report *models.Report, appName string, existingTopicID int) (int, error) {
	if m.dryRun {
		zap.S().Infof("DRY RUN: Would send Telegram notification to forum topic app=%s",
			appName,
		)
		return existingTopicID, nil
	}

	zap.S().Infof("Sending Telegram notification to forum topic app=%s", appName)

	topicID, err := tg.SendToTopic(ctx, report, appName, existingTopicID)
	if err != nil {
		zap.S().Errorf("Failed to send Telegram notification app=%s error=%v",
			appName,
			err,
		)
		return topicID, err
	}

	zap.S().Infof("Telegram notification sent successfully app=%s topic_id=%d", appName, topicID)

	return topicID, nil
}

// HasEnabledNotifiers returns true if at least one notifier is enabled
func (m *Manager) HasEnabledNotifiers() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, n := range m.notifiers {
		if n.Enabled() {
			return true
		}
	}
	return false
}

// EnabledNotifiers returns the names of all enabled notifiers
func (m *Manager) EnabledNotifiers() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var names []string
	for name, n := range m.notifiers {
		if n.Enabled() {
			names = append(names, name)
		}
	}
	return names
}

// NotifyAllCombined sends a combined notification for multiple audit results from a single app.
// This is used when an app has both npm and composer auditors, sending ONE message with all results.
// Returns NotificationResult with any created/used IDs that should be persisted.
func (m *Manager) NotifyAllCombined(ctx context.Context, combinedReport *models.CombinedAppReport, config models.NotificationConfig) (*NotificationResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error
	result := &NotificationResult{}

	// Send combined email notifications
	if len(config.Email) > 0 {
		if emailNotifier, ok := m.notifiers["email"]; ok && emailNotifier.Enabled() {
			// For email, send each report individually (email supports attachments natively)
			for _, report := range combinedReport.Reports {
				if err := m.send(ctx, emailNotifier, report, config.Email); err != nil {
					errs = append(errs, fmt.Errorf("email: %w", err))
				}
			}
		}
	}

	// Send combined Telegram notification
	if config.TelegramEnabled {
		if tg, ok := m.notifiers["telegram"].(*TelegramNotifier); ok && tg.Enabled() {
			topicID, err := m.sendCombinedTelegram(ctx, tg, combinedReport, config.AppName, config.TelegramTopicID)
			if err != nil {
				errs = append(errs, fmt.Errorf("telegram: %w", err))
			}
			result.TelegramTopicID = topicID
		}
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("notification errors: %v", errs)
	}

	return result, nil
}

// sendCombinedTelegram sends a combined Telegram notification to an app's forum topic.
// Returns the topic ID used (existing or newly created).
func (m *Manager) sendCombinedTelegram(ctx context.Context, tg *TelegramNotifier, combinedReport *models.CombinedAppReport, appName string, existingTopicID int) (int, error) {
	if m.dryRun {
		zap.S().Infof("DRY RUN: Would send combined Telegram notification to forum topic app=%s reports=%d files=%d",
			appName,
			len(combinedReport.Reports),
			len(combinedReport.ReportFiles),
		)
		return existingTopicID, nil
	}

	zap.S().Infof("Sending combined Telegram notification to forum topic app=%s reports=%d",
		appName,
		len(combinedReport.Reports),
	)

	topicID, err := tg.SendCombinedToTopic(ctx, combinedReport, appName, existingTopicID)
	if err != nil {
		zap.S().Errorf("Failed to send combined Telegram notification app=%s error=%v",
			appName,
			err,
		)
		return topicID, err
	}

	zap.S().Infof("Combined Telegram notification sent successfully app=%s topic_id=%d", appName, topicID)

	return topicID, nil
}
