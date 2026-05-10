package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/pivo-agent/pivo/internal/pairing"
	"github.com/pivo-agent/pivo/internal/yubikey"
)

// JSON-RPC-like message structures

type Request struct {
	ID     int             `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     int         `json:"id"`
	Result interface{} `json:"result,omitempty"`
	Error  *RpcError   `json:"error,omitempty"`
}

type RpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type Handler struct {
	ykMgr   *yubikey.Manager
	pairing *pairing.Manager
}

func NewHandler(ykMgr *yubikey.Manager, pairingMgr *pairing.Manager) *Handler {
	return &Handler{
		ykMgr:   ykMgr,
		pairing: pairingMgr,
	}
}

func (h *Handler) Handle(origin string, raw []byte) Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return Response{Error: &RpcError{Code: 400, Message: "invalid JSON"}}
	}

	// "pair" is allowed without being paired
	if req.Method == "pair" {
		return h.handlePair(req, origin)
	}

	// All other methods require paired origin
	if !h.pairing.IsPaired(origin) {
		return Response{ID: req.ID, Error: &RpcError{Code: 403, Message: "origin not paired"}}
	}

	switch req.Method {
	case "list-readers":
		return h.handleListReaders(req)
	case "select-reader":
		return h.handleSelectReader(req)
	case "list-certificates":
		return h.handleListCertificates(req)
	case "generate-key":
		return h.handleGenerateKey(req)
	case "create-csr":
		return h.handleCreateCSR(req)
	case "import-certificate":
		return h.handleImportCertificate(req)
	default:
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: fmt.Sprintf("unknown method %q", req.Method)}}
	}
}

func (h *Handler) handlePair(req Request, origin string) Response {
	if h.pairing.IsPaired(origin) {
		return Response{ID: req.ID, Result: map[string]string{"status": "already-paired"}}
	}

	var params struct {
		PIN string `json:"pin"`
	}
	_ = json.Unmarshal(req.Params, &params)

	// If PIN provided, this is the confirmation step
	if params.PIN != "" {
		approved, err := h.pairing.ConfirmPairing(origin, params.PIN)
		if err != nil {
			log.Printf("[PIVo] pairing error: %v", err)
			return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: "pairing error"}}
		}
		if !approved {
			return Response{ID: req.ID, Error: &RpcError{Code: 403, Message: "wrong pin"}}
		}
		return Response{ID: req.ID, Result: map[string]string{"status": "paired"}}
	}

	// No PIN — initiate pairing, show PIN in console
	h.pairing.StartPairing(origin)
	return Response{ID: req.ID, Result: map[string]string{"status": "pin-required"}}
}

func (h *Handler) handleListReaders(req Request) Response {
	readers, err := h.ykMgr.ListReaders()
	if err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: readers}
}

func (h *Handler) handleSelectReader(req Request) Response {
	var params struct {
		Serial uint32 `json:"serial"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 400, Message: "invalid params: " + err.Error()}}
	}
	if err := h.ykMgr.SelectReader(params.Serial); err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: map[string]string{"status": "ok"}}
}

func (h *Handler) handleListCertificates(req Request) Response {
	yk := h.ykMgr.Selected()
	if yk == nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: "no YubiKey selected"}}
	}
	certs, err := yubikey.ListCertificates(yk)
	if err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: certs}
}

func (h *Handler) handleGenerateKey(req Request) Response {
	var params struct {
		Slot          string `json:"slot"`
		Algorithm     string `json:"algorithm"`
		PIN           string `json:"pin"`
		ManagementKey string `json:"managementKey"`
		Force         bool   `json:"force"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 400, Message: "invalid params: " + err.Error()}}
	}

	yk := h.ykMgr.Selected()
	if yk == nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: "no YubiKey selected"}}
	}

	if !params.Force {
		if occupied, _ := yubikey.SlotHasCert(yk, params.Slot); occupied {
			return Response{ID: req.ID, Error: &RpcError{Code: 409, Message: "slot " + params.Slot + " already contains a certificate, use force=true to overwrite"}}
		}
	}

	pubPEM, err := yubikey.GenerateKey(yk, params.Slot, params.Algorithm, params.ManagementKey, params.PIN)
	if err != nil {
		if errors.Is(err, yubikey.ErrPINRequired) {
			return Response{ID: req.ID, Error: &RpcError{Code: 4011, Message: err.Error()}}
		}
		return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: map[string]string{"publicKey": pubPEM}}
}

func (h *Handler) handleCreateCSR(req Request) Response {
	var params struct {
		Slot    string                `json:"slot"`
		PIN     string                `json:"pin"`
		Subject yubikey.SubjectParams `json:"subject"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 400, Message: "invalid params: " + err.Error()}}
	}

	yk := h.ykMgr.Selected()
	if yk == nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: "no YubiKey selected"}}
	}

	csrPEM, err := yubikey.CreateCSR(yk, params.Slot, params.PIN, params.Subject)
	if err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: map[string]string{"csr": csrPEM}}
}

func (h *Handler) handleImportCertificate(req Request) Response {
	var params struct {
		Slot          string `json:"slot"`
		Certificate   string `json:"certificate"`
		ManagementKey string `json:"managementKey"`
		PIN           string `json:"pin"`
		Force         bool   `json:"force"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 400, Message: "invalid params: " + err.Error()}}
	}

	yk := h.ykMgr.Selected()
	if yk == nil {
		return Response{ID: req.ID, Error: &RpcError{Code: 404, Message: "no YubiKey selected"}}
	}

	if !params.Force {
		if occupied, _ := yubikey.SlotHasCert(yk, params.Slot); occupied {
			return Response{ID: req.ID, Error: &RpcError{Code: 409, Message: "slot " + params.Slot + " already contains a certificate, use force=true to overwrite"}}
		}
	}

	if err := yubikey.ImportCertificate(yk, params.Slot, params.Certificate, params.ManagementKey, params.PIN); err != nil {
		if errors.Is(err, yubikey.ErrPINRequired) {
			return Response{ID: req.ID, Error: &RpcError{Code: 4011, Message: err.Error()}}
		}
		return Response{ID: req.ID, Error: &RpcError{Code: 500, Message: err.Error()}}
	}
	return Response{ID: req.ID, Result: map[string]string{"status": "ok"}}
}
