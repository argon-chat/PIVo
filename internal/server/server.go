package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"nhooyr.io/websocket"

	"github.com/pivo-agent/pivo/internal/pairing"
	"github.com/pivo-agent/pivo/internal/yubikey"
)

type Server struct {
	ports   []int
	handler *Handler
	srv     *http.Server
	Port    int
}

func New(ports []int, ykMgr *yubikey.Manager, pairingMgr *pairing.Manager) *Server {
	h := NewHandler(ykMgr, pairingMgr)
	return &Server{
		ports:   ports,
		handler: h,
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/health", s.handleHealth)

	var listener net.Listener
	var lastErr error
	for _, port := range s.ports {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			log.Printf("[PIVo] port %d busy, trying next...", port)
			lastErr = err
			continue
		}
		listener = l
		s.Port = port
		break
	}
	if listener == nil {
		return fmt.Errorf("failed to bind any port: %w", lastErr)
	}

	s.srv = &http.Server{Handler: mux}
	log.Printf("[PIVo] listening on ws://127.0.0.1:%d/ws", s.Port)

	return s.srv.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.writeCORSHeaders(w, r)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	s.writeCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) writeCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Header.Get("Access-Control-Request-Private-Network") == "true" {
		w.Header().Set("Access-Control-Allow-Private-Network", "true")
	}
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if host != "localhost" && host != "127.0.0.1" {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		http.Error(w, "missing Origin header", http.StatusForbidden)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("[PIVo] WebSocket accept error: %v", err)
		return
	}
	defer conn.CloseNow()

	log.Printf("[PIVo] connection from %s", origin)

	ctx := r.Context()
	for {
		_, msg, err := conn.Read(ctx)
		if err != nil {
			status := websocket.CloseStatus(err)
			if status == websocket.StatusNormalClosure ||
				status == websocket.StatusGoingAway ||
				status == websocket.StatusNoStatusRcvd ||
				strings.Contains(err.Error(), "closed") {
				log.Printf("[PIVo] disconnected %s (status=%d)", origin, status)
			} else {
				log.Printf("[PIVo] read error from %s: status=%d err=%v", origin, status, err)
			}
			return
		}

		log.Printf("[PIVo] << %s", string(msg))
		resp := s.handler.Handle(origin, msg)

		respBytes, err := json.Marshal(resp)
		if err != nil {
			log.Printf("[PIVo] marshal error: %v", err)
			continue
		}

		log.Printf("[PIVo] >> %s", string(respBytes))
		if err := conn.Write(ctx, websocket.MessageText, respBytes); err != nil {
			log.Printf("[PIVo] write error to %s: %v", origin, err)
			return
		}
	}
}
