package main

import (
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/imkira/gcp-iap-auth/jwt"
)

type server struct {
	srv        *http.Server
	listener   net.Listener
	listenAddr string
	opts       *Options
}

func NewServer() (*server, error) {
	cfg, opts, err := initConfig()
	if err != nil {
		return nil, err
	}

	return newServerByOpts(opts, cfg)
}

func NewServerWithArgs(args []string) (*server, error) {
	cfg, opts, err := initConfigByArgs(args)
	if err != nil {
		return nil, err
	}
	return newServerByOpts(opts, cfg)
}

func newServerByOpts(opts *Options, cfg *jwt.Config) (*server, error) {
	log.Printf("Matching audiences: %s\n", cfg.MatchAudiences)
	mux := http.NewServeMux()

	mux.Handle("/auth", authHandler(cfg))
	mux.HandleFunc("/healthz", healthzHandler)

	if opts.Backend != "" {
		proxy, err := newProxy(cfg, opts.Backend, opts.EmailHeader, opts.BackendInsecure)
		if err != nil {
			return nil, fmt.Errorf("prepare proxy handler : %w", err)
		}
		log.Printf("Proxying authenticated requests to backend %s", opts.Backend)
		mux.HandleFunc("/", proxy.handler)
	}

	addr := net.JoinHostPort(opts.ListenAddr, fmt.Sprintf("%d", opts.ListenPort))
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s : %w", addr, err)
	}
	httpServer := &http.Server{
		Handler: mux,
	}

	return &server{
		srv:        httpServer,
		listener:   listener,
		listenAddr: listener.Addr().String(),
		opts:       opts,
	}, nil
}

func (s *server) ListenAndServe() error {
	if s.opts.TlsCertPath != "" || s.opts.TlsKeyPath != "" {
		return s.listenAndServeHTTPS()
	}
	return s.listenAndServeHTTP()
}

func (s *server) listenAndServeHTTP() error {
	log.Printf("Listening on http://%s\n", s.listenAddr)
	if err := s.srv.Serve(s.listener); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func (s *server) listenAndServeHTTPS() error {
	log.Printf("Listening on https://%s\n", s.listenAddr)
	if err := s.srv.ServeTLS(s.listener, s.opts.TlsCertPath, s.opts.TlsKeyPath); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server error: %w", err)
	}
	return nil
}

func (s *server) Close() error {
	return s.srv.Close()
}

func (s *server) ListenAddress() string {
	return s.listenAddr
}
