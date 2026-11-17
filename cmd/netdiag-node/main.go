package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netdiag/internal/node"

	"github.com/quic-go/quic-go/http3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", ":8443", "HTTPS/TCP и HTTP3/UDP")
	udp := flag.String("udp", ":4444", "UDP echo")
	certPath := flag.String("cert", "", "TLS certificate")
	keyPath := flag.String("key", "", "TLS key")
	tokenEnv := flag.String("token-env", "NETDIAG_NODE_TOKEN", "имя переменной токена")
	maxMiB := flag.Int64("max-mib", 1024, "лимит данных на сессию")
	flag.Parse()
	token := os.Getenv(*tokenEnv)
	if len(token) < 24 {
		return fmt.Errorf("токен узла должен содержать не менее 24 байт")
	}
	if *maxMiB < 1 || *maxMiB > 16384 {
		return fmt.Errorf("max-mib: 1..16384")
	}
	cert, err := tls.LoadX509KeyPair(*certPath, *keyPath)
	if err != nil {
		return fmt.Errorf("не удалось загрузить сертификат и ключ")
	}
	udpAddr, err := net.ResolveUDPAddr("udp", *udp)
	if err != nil {
		return err
	}
	packet, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	defer packet.Close()
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	quicAddr := listener.Addr().String()
	quicPacket, err := net.ListenPacket("udp", quicAddr)
	if err != nil {
		return err
	}
	defer quicPacket.Close()
	service := node.NewServer(token, packet.LocalAddr().(*net.UDPAddr).Port, *maxMiB<<20)
	service.Caps.UDPNoFragment4, service.Caps.UDPNoFragment6 = node.FragmentationSupport(packet)
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	https := &http.Server{Handler: service, TLSConfig: config, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	h3 := &http3.Server{Handler: service, TLSConfig: config.Clone(), MaxHeaderBytes: 16384, IdleTimeout: 15 * time.Second}
	defer https.Close()
	defer h3.Close()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	errors := make(chan error, 3)
	go func() { errors <- service.ServeUDP(ctx, packet) }()
	go func() { errors <- https.ServeTLS(listener, "", "") }()
	go func() { errors <- h3.Serve(quicPacket) }()
	fmt.Fprintf(os.Stderr, "Узел запущен: HTTPS и HTTP/3 %s; UDP %s\n", listener.Addr(), packet.LocalAddr())
	select {
	case <-ctx.Done():
	case err = <-errors:
		if err != nil && err != http.ErrServerClosed {
			cancel()
		} else {
			err = nil
		}
	}
	shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	https.Shutdown(shutdown)
	h3.Shutdown(shutdown)
	return err
}
