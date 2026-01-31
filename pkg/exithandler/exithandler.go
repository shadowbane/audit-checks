package exithandler

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// ExitHandler manages graceful shutdown with cleanup callbacks.
type ExitHandler struct {
	callbacks []func()
	mu        sync.Mutex
	done      chan struct{}
}

// New creates a new ExitHandler.
func New() *ExitHandler {
	return &ExitHandler{
		callbacks: make([]func(), 0),
		done:      make(chan struct{}),
	}
}

// Register adds a cleanup callback to be executed on shutdown.
// Callbacks are executed in reverse order (LIFO).
func (h *ExitHandler) Register(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.callbacks = append(h.callbacks, fn)
}

// Listen starts listening for shutdown signals (SIGINT, SIGTERM).
// When a signal is received, it cancels the context and executes callbacks.
func (h *ExitHandler) Listen(ctx context.Context, cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		select {
		case <-sigChan:
			cancel()
			h.executeCallbacks()
			close(h.done)
		case <-ctx.Done():
			h.executeCallbacks()
			close(h.done)
		}
	}()
}

// Wait blocks until shutdown is complete.
func (h *ExitHandler) Wait() {
	<-h.done
}

// Shutdown manually triggers the shutdown sequence.
func (h *ExitHandler) Shutdown() {
	h.executeCallbacks()
	select {
	case <-h.done:
	default:
		close(h.done)
	}
}

// executeCallbacks runs all registered callbacks in reverse order.
func (h *ExitHandler) executeCallbacks() {
	h.mu.Lock()
	defer h.mu.Unlock()

	for i := len(h.callbacks) - 1; i >= 0; i-- {
		h.callbacks[i]()
	}
}
