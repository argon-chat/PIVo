package yubikey

import (
	"fmt"
	"sync"

	"github.com/go-piv/piv-go/v2/piv"
)

type ReaderInfo struct {
	Name   string `json:"name"`
	Serial uint32 `json:"serial"`
}

type Manager struct {
	mu       sync.Mutex
	selected *piv.YubiKey
	serial   uint32
}

func NewManager() *Manager {
	return &Manager{}
}

// ListReaders enumerates connected YubiKeys and returns their info.
func (m *Manager) ListReaders() ([]ReaderInfo, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("enumerate smartcards: %w", err)
	}

	var readers []ReaderInfo
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		serial, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}
		readers = append(readers, ReaderInfo{
			Name:   card,
			Serial: serial,
		})
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
	}

	cards, err := piv.Cards()
	if err != nil {
		return fmt.Errorf("enumerate smartcards: %w", err)
	}

	for _, card := range cards {
		yk, err := piv.Open(card)
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
	}
}
