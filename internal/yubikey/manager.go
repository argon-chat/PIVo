package yubikey

import (
	"fmt"
	"sync"
	"time"

	"github.com/go-piv/piv-go/v2/piv"
)

// openCardWithRetry opens a smart card, retrying a few times on transient PC/SC
// failures (reader busy, card just inserted, another process holding the handle).
func openCardWithRetry(card string) (*piv.YubiKey, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		yk, err := piv.Open(card)
		if err == nil {
			return yk, nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, lastErr
}

// listCardsWithRetry enumerates smart cards, retrying on transient PC/SC errors.
// USB/PCSC enumeration occasionally errors or returns a short list right after a
// connect/disconnect, which is why a single call can intermittently miss a reader.
func listCardsWithRetry() ([]string, error) {
	var lastErr error
	for i := 0; i < 3; i++ {
		cards, err := piv.Cards()
		if err == nil {
			return cards, nil
		}
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	return nil, lastErr
}

type ReaderInfo struct {
	Name   string `json:"name"`
	Serial uint32 `json:"serial"`
}

type Manager struct {
	mu       sync.Mutex
	selected *piv.YubiKey
	serial   uint32
	card     string // PC/SC reader name of the currently selected key
}

func NewManager() *Manager {
	return &Manager{}
}

// ListReaders enumerates connected YubiKeys and returns their info.
// Always returns a non-nil slice so it serializes to a JSON array, never null.
func (m *Manager) ListReaders() ([]ReaderInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cards, err := listCardsWithRetry()
	if err != nil {
		return nil, fmt.Errorf("enumerate smartcards: %w", err)
	}

	readers := make([]ReaderInfo, 0, len(cards))
	for _, card := range cards {
		// The currently-selected card is held open by us with exclusive access, so
		// re-opening it here would fail and drop it from the list. Report it from the
		// serial we already know instead.
		if m.selected != nil && card == m.card {
			readers = append(readers, ReaderInfo{Name: card, Serial: m.serial})
			continue
		}
		yk, err := openCardWithRetry(card)
		if err != nil {
			continue
		}
		serial, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}
		readers = append(readers, ReaderInfo{Name: card, Serial: serial})
		yk.Close()
	}
	return readers, nil
}

// SelectReader opens a YubiKey by serial number. Closes any previously selected key.
func (m *Manager) SelectReader(serial uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.selected != nil {
		m.selected.Close()
		m.selected = nil
		m.serial = 0
		m.card = ""
	}

	cards, err := listCardsWithRetry()
	if err != nil {
		return fmt.Errorf("enumerate smartcards: %w", err)
	}

	for _, card := range cards {
		yk, err := openCardWithRetry(card)
		if err != nil {
			continue
		}
		s, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}
		if s == serial {
			m.selected = yk
			m.serial = serial
			m.card = card
			return nil
		}
		yk.Close()
	}
	return fmt.Errorf("YubiKey with serial %d not found", serial)
}

// Selected returns the currently selected YubiKey. Returns nil if none selected.
func (m *Manager) Selected() *piv.YubiKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.selected
}

// SelectedSerial returns serial of the selected YubiKey.
func (m *Manager) SelectedSerial() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serial
}

// Close releases the currently selected YubiKey.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.selected != nil {
		m.selected.Close()
		m.selected = nil
		m.serial = 0
		m.card = ""
	}
}
