package pairing

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"

	"github.com/pivo-agent/pivo/internal/config"
)

type Manager struct {
	cfg     *config.Config
	mu      sync.Mutex
	pending map[string]string // origin -> pin code
}

func New(cfg *config.Config) *Manager {
	return &Manager{cfg: cfg, pending: make(map[string]string)}
}

func (m *Manager) IsPaired(origin string) bool {
	return m.cfg.IsPaired(origin)
}

// StartPairing generates a PIN, shows it in the console, and stores it for verification.
// Returns the generated PIN that the frontend must send back to confirm.
func (m *Manager) StartPairing(origin string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	pin := generatePIN()
	m.pending[origin] = pin

	fmt.Printf("\n[PIVo] Site %s wants to pair.\n", origin)
	fmt.Printf("[PIVo] Confirm PIN on the website: %s\n", pin)
	fmt.Println("[PIVo] Waiting for PIN confirmation...")

	return pin
}

// ConfirmPairing verifies the PIN sent by the frontend.
func (m *Manager) ConfirmPairing(origin, pin string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	expected, ok := m.pending[origin]
	if !ok {
		return false, fmt.Errorf("no pending pairing for origin %s", origin)
	}
	delete(m.pending, origin)

	if pin != expected {
		log.Printf("[PIVo] wrong PIN from %s.", origin)
		return false, nil
	}

	if err := m.cfg.AddOrigin(origin); err != nil {
		return false, err
	}
	if err := m.cfg.Save(); err != nil {
		return false, err
	}
	log.Printf("[PIVo] origin %s paired.", origin)
	return true, nil
}

// RequestPairing is the legacy console-interactive flow (y/n prompt).
func (m *Manager) RequestPairing(origin string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fmt.Printf("\n[PIVo] Site %s wants to connect.\n", origin)
	fmt.Print("[PIVo] Allow? (y/n): ")

	reader := bufio.NewReader(os.Stdin)
	answer, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	answer = strings.TrimSpace(strings.ToLower(answer))

	if answer == "y" || answer == "yes" {
		if err := m.cfg.AddOrigin(origin); err != nil {
			return false, err
		}
		if err := m.cfg.Save(); err != nil {
			return false, err
		}
		log.Printf("[PIVo] origin %s paired.", origin)
		return true, nil
	}

	log.Printf("[PIVo] connection from %s rejected.", origin)
	return false, nil
}

func generatePIN() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(999999))
	return fmt.Sprintf("%06d", n.Int64())
}

func (m *Manager) Unpair(origin string) bool {
	removed := m.cfg.RemoveOrigin(origin)
	if removed {
		_ = m.cfg.Save()
	}
	return removed
}

func (m *Manager) ListOrigins() []string {
	return m.cfg.Origins()
}
