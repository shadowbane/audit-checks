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

// NotifyAll sends notifications using all configured notifiers
func (m *Manager) NotifyAll(ctx context.Context, report *models.Report, config models.NotificationConfig) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var errs []error

	// Send email notifications
	if len(config.Email) > 0 {
		if emailNotifier, ok := m.notifiers["email"]; ok && emailNotifier.Enabled() {
			if err := m.send(ctx, emailNotifier, report, config.Email); err != nil {
				errs = append(errs, fmt.Errorf("email: %w", err))
			}
		}
	}

	// Send Telegram notifications
	if len(config.Telegram) > 0 {
		if telegramNotifier, ok := m.notifiers["telegram"]; ok && telegramNotifier.Enabled() {
			if err := m.send(ctx, telegramNotifier, report, config.Telegram); err != nil {
				errs = append(errs, fmt.Errorf("telegram: %w", err))
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("notification errors: %v", errs)
	}

	return nil
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
