package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

// QUICTransport 提供可选的 QUIC 级联传输（仅 TCP）。
type QUICTransport struct {
	Self            NodeID
	ListenAddr      string
	Endpoints       map[NodeID]string
	TLSConfig       *tls.Config
	ServerName      string
	MaxIdleTimeout  time.Duration
	MaxDatagramSize int
	AuthKey         []byte
	Metrics         *Metrics
	Compression     string
	CompressMin     int
}

func (t *QUICTransport) Forward(ctx context.Context, src NodeID, path []NodeID, proto Protocol, downstream net.Conn, remoteAddr string) error {
	if proto != ProtocolTCP {
		return fmt.Errorf("quic transport currently supports tcp only")
	}
	if len(path) < 2 {
		return fmt.Errorf("path too short: %v", path)
	}
	next := path[1]
	target, ok := t.Endpoints[next]
	if !ok {
		return fmt.Errorf("no endpoint for %s", next)
	}
	if !strings.Contains(target, "://") {
		target = "quic://" + strings.TrimPrefix(target, "//")
	}
	parsed, err := normalizeDialAddr(target)
	if err != nil {
		return err
	}
	tlsConf := cloneTLSWithServerName(t.TLSConfig, t.ServerName)
	qconf := &quic.Config{}
	if t.MaxIdleTimeout > 0 {
		qconf.MaxIdleTimeout = t.MaxIdleTimeout
	}
	qconn, err := quic.DialAddr(ctx, parsed, tlsConf, qconf)
	if err != nil {
		downstream.Close()
		return fmt.Errorf("dial quic %s failed: %w", parsed, err)
	}
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		downstream.Close()
		return fmt.Errorf("open quic stream failed: %w", err)
	}
	header := ControlHeader{
		Path:        path[1:],
		RemoteAddr:  remoteAddr,
		Proto:       proto,
		Compression: t.Compression,
		CompressMin: t.CompressMin,
	}
	if err := writeSignedEnvelopeStream(stream, ControlEnvelope{
		Type:    "header",
		Session: newSessionID(),
		Header:  &header,
	}, t.AuthKey); err != nil {
		downstream.Close()
		stream.Close()
		qconn.CloseWithError(0, "header write failed")
		return err
	}
	ack, err := readVerifiedEnvelopeStream(stream, t.AuthKey)
	if err != nil {
		downstream.Close()
		stream.Close()
		qconn.CloseWithError(0, "ack failed")
		return err
	}
	if ack.Type != "ack" {
		downstream.Close()
		stream.Close()
		qconn.CloseWithError(0, "no ack")
		return fmt.Errorf("expected ack, got %s: %s", ack.Type, ack.Error)
	}
	log.Printf("[quic] downstream %s confirmed path", next)
	return bridgeMaybeCompressed(sessionFromAck(ack), downstream, newStreamConn(stream, qconn), t.Compression, t.CompressMin, t.Metrics, path, remoteAddr)
}

func (t *QUICTransport) handleTCPExit(ctx context.Context, session string, upstream net.Conn, remoteAddr string, compression string, compressMin int) error {
	out, err := net.DialTimeout("tcp", remoteAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial remote %s failed: %w", remoteAddr, err)
	}
	if err := writeSignedEnvelopeStream(upstream, ControlEnvelope{
		Type:    "ack",
		Session: session,
		Ack:     &AckStatus{Confirmed: []NodeID{t.Self}, Note: "exit connected"},
	}, t.AuthKey); err != nil {
		out.Close()
		return fmt.Errorf("send exit ack failed: %w", err)
	}
	return bridgeMaybeCompressed(session, out, upstream, compression, compressMin, t.Metrics, nil, remoteAddr)
}

func (t *QUICTransport) ReconnectTCP(ctx context.Context, src NodeID, proto Protocol, downstream net.Conn, remoteAddr string, computePath func(try int) ([]NodeID, error), attempts int) error {
	if proto != ProtocolTCP {
		return fmt.Errorf("quic transport supports tcp only")
	}
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		path, err := computePath(i)
		if err != nil {
			time.Sleep(200 * time.Millisecond)
			continue
		}
		err = t.Forward(ctx, src, path, proto, downstream, remoteAddr)
		if err == nil {
			return nil
		}
		log.Printf("[quic reconnect %d/%d] failed: %v", i+1, attempts, err)
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("reconnect attempts exhausted")
}

func (t *QUICTransport) Serve(ctx context.Context) error {
	qconf := &quic.Config{}
	if t.MaxIdleTimeout > 0 {
		qconf.MaxIdleTimeout = t.MaxIdleTimeout
	}
	tlsConf := cloneTLSWithServerName(t.TLSConfig, t.ServerName)
	// 在 server 侧允许无 SNI 握手：ServerName 为空且 InsecureSkipVerify true。
	tlsConf.ServerName = ""
	tlsConf.InsecureSkipVerify = true
	listener, err := quic.ListenAddr(t.ListenAddr, tlsConf, qconf)
	if err != nil {
		return err
	}
	log.Printf("QUIC transport listening on %s", t.ListenAddr)
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Printf("quic accept failed: %v", err)
			continue
		}
		go t.handleConn(ctx, conn)
	}
}

func (t *QUICTransport) handleConn(ctx context.Context, conn *quic.Conn) {
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go t.handleStream(ctx, conn, stream)
	}
}

func (t *QUICTransport) handleStream(ctx context.Context, conn *quic.Conn, stream *quic.Stream) {
	env, err := readVerifiedEnvelopeStream(stream, t.AuthKey)
	if err != nil {
		log.Printf("[quic] read header failed: %v", err)
		stream.Close()
		return
	}
	if env.Type != "header" || env.Header == nil {
		stream.Close()
		return
	}
	header := *env.Header
	if len(header.Path) == 0 || header.Path[0] != t.Self {
		stream.Close()
		return
	}
	remaining := header.Path[1:]
	session := sessionFromAck(env)

	if len(remaining) == 0 {
		if header.Proto != ProtocolTCP {
			writeSignedEnvelopeStream(stream, ControlEnvelope{Type: "error", Error: "quic only supports tcp"}, t.AuthKey)
			stream.Close()
			return
		}
		if err := t.handleTCPExit(ctx, session, newStreamConn(stream, conn), header.RemoteAddr, header.Compression, header.CompressMin); err != nil {
			writeSignedEnvelopeStream(stream, ControlEnvelope{Type: "error", Error: err.Error()}, t.AuthKey)
		}
		return
	}

	next := remaining[0]
	target, ok := t.Endpoints[next]
	if !ok {
		writeSignedEnvelopeStream(stream, ControlEnvelope{Type: "error", Error: "no endpoint for next"}, t.AuthKey)
		stream.Close()
		return
	}
	if !strings.Contains(target, "://") {
		target = "quic://" + target
	}
	addr, err := normalizeDialAddr(target)
	if err != nil {
		writeSignedEnvelopeStream(stream, ControlEnvelope{Type: "error", Error: err.Error()}, t.AuthKey)
		return
	}
	qconn, err := quic.DialAddr(ctx, addr, t.TLSConfig, nil)
	if err != nil {
		writeSignedEnvelopeStream(stream, ControlEnvelope{Type: "error", Error: err.Error()}, t.AuthKey)
		return
	}
	nextStream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		stream.Close()
		qconn.CloseWithError(0, "open downstream failed")
		return
	}
	if err := writeSignedEnvelopeStream(nextStream, ControlEnvelope{
		Type:    "header",
		Session: env.Session,
		Header: &ControlHeader{
			Path:        remaining,
			RemoteAddr:  header.RemoteAddr,
			Proto:       header.Proto,
			Compression: header.Compression,
			CompressMin: header.CompressMin,
		},
	}, t.AuthKey); err != nil {
		stream.Close()
		nextStream.Close()
		qconn.CloseWithError(0, "write header failed")
		return
	}
	ack, err := readVerifiedEnvelopeStream(nextStream, t.AuthKey)
	if err != nil {
		stream.Close()
		nextStream.Close()
		qconn.CloseWithError(0, "ack failed")
		return
	}
	if ack.Type != "ack" {
		stream.Close()
		nextStream.Close()
		qconn.CloseWithError(0, "no ack")
		return
	}
	writeSignedEnvelopeStream(stream, ControlEnvelope{
		Type: "ack",
		Ack:  &AckStatus{Confirmed: append([]NodeID{t.Self}, ack.Ack.Confirmed...)},
	}, t.AuthKey)
	// 中间跳不做压缩/解压，只透传压缩后的数据，出口再解压。
	if err := bridgeMaybeCompressed(session, newStreamConn(stream, conn), newStreamConn(nextStream, qconn), "none", 0, t.Metrics, header.Path, header.RemoteAddr); err != nil {
		log.Printf("[quic] bridge failed: %v", err)
	}
}

func writeSignedEnvelopeStream(w io.Writer, env ControlEnvelope, key []byte) error {
	if env.Version == 0 {
		env.Version = 1
	}
	if env.Timestamp == 0 {
		env.Timestamp = time.Now().UnixMilli()
	}
	if len(key) > 0 {
		if err := signEnvelope(&env, key); err != nil {
			return err
		}
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if sw, ok := w.(interface{ Flush() error }); ok {
		sw.Flush()
	}
	return nil
}

func readVerifiedEnvelopeStream(r io.Reader, key []byte) (ControlEnvelope, error) {
	var env ControlEnvelope
	dec := json.NewDecoder(r)
	if err := dec.Decode(&env); err != nil {
		return env, err
	}
	if env.Version != 1 {
		return env, fmt.Errorf("unsupported version %d", env.Version)
	}
	if len(key) > 0 {
		if err := verifyEnvelope(&env, key); err != nil {
			return env, err
		}
	}
	return env, nil
}

type streamConn struct {
	s          *quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
}

func newStreamConn(s *quic.Stream, parent *quic.Conn) streamConn {
	var la, ra net.Addr
	if parent != nil {
		la = parent.LocalAddr()
		ra = parent.RemoteAddr()
	}
	return streamConn{s: s, localAddr: la, remoteAddr: ra}
}

func (s streamConn) Read(p []byte) (int, error)         { return s.s.Read(p) }
func (s streamConn) Write(p []byte) (int, error)        { return s.s.Write(p) }
func (s streamConn) Close() error                       { return s.s.Close() }
func (s streamConn) LocalAddr() net.Addr                { return s.localAddr }
func (s streamConn) RemoteAddr() net.Addr               { return s.remoteAddr }
func (s streamConn) SetDeadline(t time.Time) error      { return s.s.SetDeadline(t) }
func (s streamConn) SetReadDeadline(t time.Time) error  { return s.s.SetReadDeadline(t) }
func (s streamConn) SetWriteDeadline(t time.Time) error { return s.s.SetWriteDeadline(t) }

func normalizeDialAddr(raw string) (string, error) {
	if strings.HasPrefix(raw, "quic://") {
		raw = strings.TrimPrefix(raw, "quic://")
	}
	if !strings.Contains(raw, ":") {
		return "", fmt.Errorf("invalid quic addr %s", raw)
	}
	return raw, nil
}

func sessionFromAck(env ControlEnvelope) string {
	if env.Session != "" {
		return env.Session
	}
	return newSessionID()
}
