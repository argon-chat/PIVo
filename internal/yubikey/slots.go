package yubikey

import (
	"fmt"

	"github.com/go-piv/piv-go/v2/piv"
)

var slotMap = map[string]piv.Slot{
	"9a": piv.SlotAuthentication,
	"9c": piv.SlotSignature,
	"9d": piv.SlotKeyManagement,
	"9e": piv.SlotCardAuthentication,
}

var slotNames = map[piv.Slot]string{
	piv.SlotAuthentication:     "9a",
	piv.SlotSignature:          "9c",
	piv.SlotKeyManagement:      "9d",
	piv.SlotCardAuthentication: "9e",
}

func ParseSlot(s string) (piv.Slot, error) {
	slot, ok := slotMap[s]
	if !ok {
		return piv.Slot{}, fmt.Errorf("unknown slot %q, expected: 9a, 9c, 9d, 9e", s)
	}
	return slot, nil
}

func SlotName(s piv.Slot) string {
	name, ok := slotNames[s]
	if !ok {
		return fmt.Sprintf("%02x", s.Key)
	}
	return name
}

func AllSlots() []piv.Slot {
	return []piv.Slot{
		piv.SlotAuthentication,
		piv.SlotSignature,
		piv.SlotKeyManagement,
		piv.SlotCardAuthentication,
	}
}

// SlotHasCert checks if the given slot already contains a certificate.
func SlotHasCert(yk *piv.YubiKey, slotStr string) (bool, error) {
	slot, err := ParseSlot(slotStr)
	if err != nil {
		return false, err
	}
	_, err = yk.Certificate(slot)
	if err != nil {
		return false, nil
	}
	return true, nil
}
