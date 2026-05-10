package yubikey

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
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

// ErrPINRequired is returned when the management key is PIN-protected but no PIN was provided.
var ErrPINRequired = fmt.Errorf("PIN required: management key is protected by PIN")

// resolveManagementKey returns the management key to use.
// Priority: explicit hex key > PIN-protected key from metadata > default key.
func resolveManagementKey(yk *pivlib.YubiKey, mgmtKeyHex, pin string) ([]byte, error) {
	if mgmtKeyHex != "" {
		return parseManagementKey(mgmtKeyHex)
	}

	// Try PIN-protected management key retrieval.
	// Attempt with user PIN first, then default PIN.
	pins := []string{}
	if pin != "" {
		pins = append(pins, pin)
	}
	if pin != DefaultPIN {
		pins = append(pins, DefaultPIN)
	}

	for _, p := range pins {
		meta, err := yk.Metadata(p)
		if err == nil && meta.ManagementKey != nil {
			return *meta.ManagementKey, nil
		}
	}

	// No PIN-protected key found. If the user provided a PIN, they expected
	// PIN-protected mode — return an explicit error.
	if pin != "" {
		return nil, ErrPINRequired
	}

	// No PIN provided, no PIN-protected key — fall back to default management key.
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
		return "", fmt.Errorf("generate key: %w", err)
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

	cert, err := yk.Certificate(slot)
	if err != nil {
		// No cert in slot — try to get the attestation cert to find the public key
		cert, err = yk.Attest(slot)
		if err != nil {
			return "", fmt.Errorf("cannot determine public key in slot %s: no certificate or attestation found", slotStr)
		}
	}

	if pin == "" {
		pin = DefaultPIN
	}
	priv, err := yk.PrivateKey(slot, cert.PublicKey, pivlib.KeyAuth{PIN: pin})
	if err != nil {
		return "", fmt.Errorf("access private key: %w", err)
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

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return "", fmt.Errorf("create CSR: %w", err)
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
