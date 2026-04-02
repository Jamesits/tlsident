package server

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"tlsident/pkg/api"
	"tlsident/pkg/api/anthropic"
	"tlsident/pkg/api/peetws"
	"tlsident/pkg/capture"
	"tlsident/pkg/certutil"
	"tlsident/pkg/httpfp"
	"tlsident/pkg/tlsfp"
)

type Config struct {
	ListenAddress string
	OutputDir     string
	Logger        *slog.Logger
}

type Server struct {
	config       Config
	listener     net.Listener
	tlsConfig    *tls.Config
	handler      api.Handler
	http1Handler *httpfp.HTTP1Handler
	http2Handler *httpfp.HTTP2Handler
	waitGroup    sync.WaitGroup
}

func New(config Config) (*Server, error) {
	if config.ListenAddress == "" {
		config.ListenAddress = ":8443"
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}

	certificate, err := certutil.GenerateLocalhostCertificate()
	if err != nil {
		return nil, fmt.Errorf("generate certificate: %w", err)
	}

	writer, err := capture.NewOutputWriter(config.OutputDir)
	if err != nil {
		return nil, fmt.Errorf("configure output writer: %w", err)
	}

	store := capture.NewStore(writer)
	handler := api.NewRouter(
		anthropic.NewService(store, config.Logger),
		peetws.NewService(),
	)

	return &Server{
		config: config,
		tlsConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"h2", "http/1.1"},
		},
		handler:      handler,
		http1Handler: httpfp.NewHTTP1Handler(handler, config.Logger),
		http2Handler: httpfp.NewHTTP2Handler(handler, config.Logger),
	}, nil
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	baseListener, err := net.Listen("tcp", s.config.ListenAddress)
	if err != nil {
		return err
	}
	s.listener = tlsfp.NewListener(baseListener)
	defer s.listener.Close()

	errCh := make(chan error, 1)
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()

	s.config.Logger.Info("tlsident listening",
		"url", "https://localhost"+normalizeAddress(s.config.ListenAddress),
		"output_dir", s.config.OutputDir,
	)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			select {
			case errCh <- err:
			default:
			}
			continue
		}

		observedConn, ok := conn.(*tlsfp.ObservedConn)
		if !ok {
			_ = conn.Close()
			continue
		}

		s.waitGroup.Add(1)
		go func() {
			defer s.waitGroup.Done()
			s.handleConnection(observedConn)
		}()
	}

	s.waitGroup.Wait()
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}

func (s *Server) handleConnection(conn *tlsfp.ObservedConn) {
	_ = conn.SetDeadline(time.Now().Add(2 * time.Minute))
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return
	}

	clientHello := conn.ClientHello()
	if clientHello == nil {
		_ = tlsConn.Close()
		return
	}

	tlsInfo := clientHello.CaptureTLSInfo()
	connectionInfo := conn.ConnectionInfo()
	clientPort := remotePort(conn.RemoteAddr())

	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		if err := s.http2Handler.Serve(tlsConn, connectionInfo, clientHello, tlsInfo, clientPort); err != nil {
			s.config.Logger.Error("http/2 connection error", "client_ip", connectionInfo.ClientIP, "err", err)
		}
	default:
		if err := s.http1Handler.Serve(tlsConn, connectionInfo, clientHello, tlsInfo, clientPort); err != nil {
			s.config.Logger.Error("http/1.1 connection error", "client_ip", connectionInfo.ClientIP, "err", err)
		}
	}
}

func normalizeAddress(address string) string {
	if address == "" {
		return ":8443"
	}
	if address[0] == ':' {
		return address
	}
	return ":" + address
}

func remotePort(addr net.Addr) int {
	if addr == nil {
		return 0
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return value
}
