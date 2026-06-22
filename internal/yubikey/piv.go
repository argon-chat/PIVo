package yubikey

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	pivlib "github.com/go-piv/piv-go/v2/piv"
)

type CertInfo struct {
	Subject  string `json:"subject"`
	Issuer   string `json:"issuer"`
	NotAfter string `json:"notAfter"`
	PEM      string `json:"pem"`
}

type SubjectParams struct {
	CN string `json:"CN"`
	O  string `json:"O,omitempty"`
	OU string `json:"OU,omitempty"`
}

// Default YubiKey PIV management key (factory default).
var DefaultManagementKey = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
}

// DefaultPIN is the factory default PIV PIN.
const DefaultPIN = "123456"

func parseManagementKey(hexKey string) ([]byte, error) {
	if hexKey == "" {
		return DefaultManagementKey, nil
	}
	b, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("invalid management key hex: %w", err)
	}
	if len(b) != 24 {
		return nil, fmt.Errorf("management key must be 24 bytes, got %d", len(b))
	}
	return b, nil
}

// ErrPINRequired is returned when an operation needs a PIN but none was provided.
// We never substitute a guessed/default PIN, because a wrong attempt decrements the
// YubiKey PIN retry counter and can permanently block the key.
var ErrPINRequired = fmt.Errorf("PIN required: a YubiKey PIN must be provided for this operation")

// ErrPINBlocked is returned when the PIN retry counter is already exhausted.
// The key cannot be unlocked without the PUK.
var ErrPINBlocked = fmt.Errorf("PIN is blocked: no retries remaining, a PUK reset is required")

// InvalidPINError is returned when a PIN verification fails. It carries the number
// of attempts remaining so the caller can warn the user before the key locks.
type InvalidPINError struct {
	Retries int
}

func (e *InvalidPINError) Error() string {
	if e.Retries <= 0 {
		return "invalid PIN: the key is now blocked, a PUK reset is required"
	}
	if e.Retries == 1 {
		return "invalid PIN: 1 attempt remaining before the key is blocked"
	}
	return fmt.Sprintf("invalid PIN: %d attempts remaining", e.Retries)
}

// PINRetries reports how many PIN attempts remain. This is a read-only query and
// does NOT consume an attempt.
func PINRetries(yk *pivlib.YubiKey) (int, error) {
	return yk.Retries()
}

// ensurePINUsable refuses to attempt a PIN verification when the counter is already
// exhausted, so we never waste the "last" call on an already-blocked key. If the
// retry count cannot be read we proceed (the operation itself will surface the error).
func ensurePINUsable(yk *pivlib.YubiKey) error {
	n, err := yk.Retries()
	if err != nil {
		return nil
	}
	if n <= 0 {
		return ErrPINBlocked
	}
	return nil
}

// classifyPINError converts a low-level piv auth error into an InvalidPINError that
// preserves the remaining retry count. Non-PIN errors are returned unchanged.
func classifyPINError(err error) error {
	if err == nil {
		return nil
	}
	var ae pivlib.AuthErr
	if errors.As(err, &ae) {
		return &InvalidPINError{Retries: ae.Retries}
	}
	return err
}

// resolveManagementKey returns the management key to use.
// Priority: explicit hex key > PIN-protected key from metadata > default key.
//
// IMPORTANT: we only probe the management-key metadata with the PIN the caller
// supplied. We never fall back to guessing the default PIN, because each wrong
// PIN verification decrements the retry counter and can block the key.
func resolveManagementKey(yk *pivlib.YubiKey, mgmtKeyHex, pin string) ([]byte, error) {
	if mgmtKeyHex != "" {
		return parseManagementKey(mgmtKeyHex)
	}

	// Without a PIN we cannot safely detect a PIN-protected management key
	// (probing would require guessing). Assume the default management key; if the
	// key is actually PIN-protected the operation fails on management-key auth,
	// which does NOT consume a PIN attempt.
	if pin == "" {
		return DefaultManagementKey, nil
	}

	// Reading PIN-protected metadata verifies the PIN, so guard against a blocked key first.
	if err := ensurePINUsable(yk); err != nil {
		return nil, err
	}

	meta, err := yk.Metadata(pin)
	if err != nil {
		// Surface a wrong-PIN error with the remaining retry count; do not guess further.
		return nil, classifyPINError(err)
	}
	if meta.ManagementKey != nil {
		return *meta.ManagementKey, nil
	}

	// PIN is valid but the management key is not PIN-protected — use the default key.
	return DefaultManagementKey, nil
}

func parseAlgorithm(alg string) (pivlib.Algorithm, error) {
	switch alg {
	case "RSA1024":
		return pivlib.AlgorithmRSA1024, nil
	case "RSA2048", "":
		return pivlib.AlgorithmRSA2048, nil
	case "RSA3072":
		return pivlib.AlgorithmRSA3072, nil
	case "RSA4096":
		return pivlib.AlgorithmRSA4096, nil
	case "EC256", "ECCP256":
		return pivlib.AlgorithmEC256, nil
	case "EC384", "ECCP384":
		return pivlib.AlgorithmEC384, nil
	case "Ed25519":
		return pivlib.AlgorithmEd25519, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm %q", alg)
	}
}

// ListCertificates reads certificates from all 4 standard PIV slots.
func ListCertificates(yk *pivlib.YubiKey) (map[string]*CertInfo, error) {
	result := make(map[string]*CertInfo)
	for _, slot := range AllSlots() {
		name := SlotName(slot)
		cert, err := yk.Certificate(slot)
		if err != nil {
			result[name] = nil
			continue
		}
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})
		result[name] = &CertInfo{
			Subject:  cert.Subject.String(),
			Issuer:   cert.Issuer.String(),
			NotAfter: cert.NotAfter.Format("2006-01-02T15:04:05Z"),
			PEM:      string(certPEM),
		}
	}
	return result, nil
}

// GenerateKey generates a new key pair on the YubiKey in the specified slot.
// Returns the public key in PEM format.
func GenerateKey(yk *pivlib.YubiKey, slotStr, algStr, mgmtKeyHex, pin string) (string, error) {
	slot, err := ParseSlot(slotStr)
	if err != nil {
		return "", err
	}
	mgmtKey, err := resolveManagementKey(yk, mgmtKeyHex, pin)
	if err != nil {
		return "", err
	}
	alg, err := parseAlgorithm(algStr)
	if err != nil {
		return "", err
	}

	opts := pivlib.Key{
		Algorithm:   alg,
		PINPolicy:   pivlib.PINPolicyOnce,
		TouchPolicy: pivlib.TouchPolicyNever,
	}

	pub, err := yk.GenerateKey(mgmtKey, slot, opts)
	if err != nil {
		return "", fmt.Errorf("generate key: %w", classifyPINError(err))
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	})
	return string(pubPEM), nil
}

// CreateCSR creates a Certificate Signing Request using the key in the specified slot.
// The CSR is signed on the YubiKey hardware — the private key never leaves the device.
func CreateCSR(yk *pivlib.YubiKey, slotStr, pin string, subject SubjectParams) (string, error) {
	slot, err := ParseSlot(slotStr)
	if err != nil {
		return "", err
	}

	// Signing the CSR requires a PIN verification. Never guess a default PIN —
	// a wrong attempt decrements the retry counter and can block the key.
	if pin == "" {
		return "", ErrPINRequired
	}
	if err := ensurePINUsable(yk); err != nil {
		return "", err
	}

	cert, err := yk.Certificate(slot)
	if err != nil {
		// No cert in slot — try to get the attestation cert to find the public key
		cert, err = yk.Attest(slot)
		if err != nil {
			return "", fmt.Errorf("cannot determine public key in slot %s: no certificate or attestation found", slotStr)
		}
	}

	priv, err := yk.PrivateKey(slot, cert.PublicKey, pivlib.KeyAuth{PIN: pin})
	if err != nil {
		return "", fmt.Errorf("access private key: %w", classifyPINError(err))
	}

	name := pkix.Name{}
	if subject.CN != "" {
		name.CommonName = subject.CN
	}
	if subject.O != "" {
		name.Organization = []string{subject.O}
	}
	if subject.OU != "" {
		name.OrganizationalUnit = []string{subject.OU}
	}

	template := &x509.CertificateRequest{
		Subject: name,
	}

	// PIN verification for a PINPolicyOnce key happens lazily on the first signing
	// operation, so a wrong PIN surfaces here — classify it to expose retries.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", classifyPINError(err))
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return string(csrPEM), nil
}

// ImportCertificate writes a PEM-encoded certificate into the specified slot.
func ImportCertificate(yk *pivlib.YubiKey, slotStr, certPEM, mgmtKeyHex, pin string) error {
	slot, err := ParseSlot(slotStr)
	if err != nil {
		return err
	}
	mgmtKey, err := resolveManagementKey(yk, mgmtKeyHex, pin)
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	if err := yk.SetCertificate(mgmtKey, slot, cert); err != nil {
		return fmt.Errorf("write certificate to slot %s: %w", slotStr, err)
	}
	return nil
}
