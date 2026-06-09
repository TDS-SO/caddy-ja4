// Package ja4 is a small, self-contained Caddy module that computes the base
// JA4 TLS client fingerprint (BSD-3-Clause algorithm, via github.com/exaring/ja4plus)
// at the edge and exposes it to HTTP handlers as {http.vars.ja4} and an upstream
// request header.
//
// Only base JA4 (TLS) is used — it is BSD-3-Clause and fine for commercial use.
// JA4+ variants (JA4H/JA4T/…) are deliberately NOT implemented (FoxIO License 1.1
// is not permissive for monetization).
//
// Topology: the user's Caddy proxy terminates TLS, so it is the only place that
// sees the visitor's ClientHello. This module captures JA4 there and forwards it
// to the main server as a header. If anything fails, it degrades gracefully:
// JA4 is simply empty and the request proceeds unchanged.
//
// UNTESTED SCAFFOLD: build with `xcaddy build --with github.com/TDS-SO/caddy-ja4`
// and validate on a staging proxy before any fleet rollout.
package ja4

import (
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/exaring/ja4plus"
)

func init() {
	caddy.RegisterModule(ListenerWrapper{})
	caddy.RegisterModule(Handler{})
	httpcaddyfile.RegisterHandlerDirective("ja4", parseHandlerCaddyfile)
}

// store maps an active connection's RemoteAddr -> JA4 string. RemoteAddr (ip:port)
// is unique per live connection; the entry is removed when the connection closes.
var store sync.Map // map[string]string

// ---------------------------------------------------------------------------
// Listener wrapper: caddy.listeners.ja4
// ---------------------------------------------------------------------------

// ListenerWrapper captures the ClientHello and computes JA4 before TLS termination.
// MUST be placed before the `tls` listener wrapper in the chain.
type ListenerWrapper struct{}

func (ListenerWrapper) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.ja4",
		New: func() caddy.Module { return new(ListenerWrapper) },
	}
}

func (ListenerWrapper) WrapListener(l net.Listener) net.Listener { return &ja4Listener{l} }

func (ListenerWrapper) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

type ja4Listener struct{ net.Listener }

func (l *ja4Listener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &ja4Conn{Conn: c}, nil
}

// ja4Conn peeks the ClientHello on first read, computes JA4, then replays the
// peeked bytes so the normal TLS handshake is unaffected.
type ja4Conn struct {
	net.Conn
	buf    []byte
	parsed bool
}

func (c *ja4Conn) Read(p []byte) (int, error) {
	if !c.parsed {
		c.parsed = true
		c.peekAndFingerprint()
	}
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

func (c *ja4Conn) Close() error {
	store.Delete(c.RemoteAddr().String())
	return c.Conn.Close()
}

// peekAndFingerprint reads the first TLS record (the ClientHello), buffers it for
// replay, parses it, and stores the JA4 keyed by RemoteAddr. All failures are
// silent: buf still holds whatever was read, so the handshake proceeds.
func (c *ja4Conn) peekAndFingerprint() {
	hdr := make([]byte, 5)
	if _, err := readFull(c.Conn, hdr); err != nil {
		c.buf = hdr[:0]
		return
	}
	// 0x16 = handshake record. Anything else (e.g. plain HTTP on :80) — passthrough.
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if hdr[0] != 0x16 || recLen <= 0 || recLen > 1<<16 {
		c.buf = hdr
		return
	}
	body := make([]byte, recLen)
	n, _ := readFull(c.Conn, body)
	c.buf = append(hdr, body[:n]...) // replay exactly what we consumed

	hello, ok := parseClientHello(body[:n])
	if !ok {
		return
	}
	store.Store(c.RemoteAddr().String(), ja4plus.JA4(hello))
}

func readFull(c net.Conn, p []byte) (int, error) {
	got := 0
	for got < len(p) {
		n, err := c.Read(p[got:])
		got += n
		if err != nil {
			return got, err
		}
	}
	return got, nil
}

// ---------------------------------------------------------------------------
// ClientHello parser -> tls.ClientHelloInfo (only the fields JA4 needs)
// ---------------------------------------------------------------------------

func parseClientHello(b []byte) (*tls.ClientHelloInfo, bool) {
	r := cursor{b: b}
	if r.u8() != 1 { // handshake type: client_hello
		return nil, false
	}
	r.skip(3)           // handshake length (uint24)
	r.skip(2)           // client_version
	r.skip(32)          // random
	r.skip(int(r.u8())) // session_id
	cs := r.list16u16() // cipher_suites
	r.skip(int(r.u8())) // compression_methods
	if r.err {
		return nil, false
	}

	hello := &tls.ClientHelloInfo{CipherSuites: cs}

	extTotal := int(r.u16())
	end := r.pos + extTotal
	for r.pos < end && !r.err {
		etype := r.u16()
		elen := int(r.u16())
		data := r.bytes(elen)
		if r.err {
			break
		}
		hello.Extensions = append(hello.Extensions, etype)
		switch etype {
		case 0x0000: // server_name
			hello.ServerName = parseSNI(data)
		case 0x0010: // ALPN
			hello.SupportedProtos = parseALPN(data)
		case 0x000d: // signature_algorithms
			hello.SignatureSchemes = parseSigSchemes(data)
		case 0x002b: // supported_versions
			hello.SupportedVersions = parseSupportedVersions(data)
		}
	}
	return hello, true
}

func parseSNI(d []byte) string {
	c := cursor{b: d}
	c.skip(2)        // server_name_list length
	if c.u8() != 0 { // name_type host_name(0)
		return ""
	}
	return string(c.bytes(int(c.u16())))
}

func parseALPN(d []byte) []string {
	c := cursor{b: d}
	c.skip(2) // protocol_name_list length
	var out []string
	for c.pos < len(c.b) && !c.err {
		out = append(out, string(c.bytes(int(c.u8()))))
	}
	return out
}

func parseSigSchemes(d []byte) []tls.SignatureScheme {
	c := cursor{b: d}
	c.skip(2) // list length
	var out []tls.SignatureScheme
	for c.pos+1 < len(c.b) && !c.err {
		out = append(out, tls.SignatureScheme(c.u16()))
	}
	return out
}

func parseSupportedVersions(d []byte) []uint16 {
	c := cursor{b: d}
	c.skip(1) // list length (1 byte)
	var out []uint16
	for c.pos+1 < len(c.b) && !c.err {
		out = append(out, c.u16())
	}
	return out
}

// cursor is a tiny bounds-checked big-endian reader.
type cursor struct {
	b   []byte
	pos int
	err bool
}

func (c *cursor) need(n int) bool {
	if c.err || c.pos+n > len(c.b) {
		c.err = true
		return false
	}
	return true
}
func (c *cursor) u8() uint8 {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return v
}
func (c *cursor) u16() uint16 {
	if !c.need(2) {
		return 0
	}
	v := binary.BigEndian.Uint16(c.b[c.pos:])
	c.pos += 2
	return v
}
func (c *cursor) skip(n int) {
	if c.need(n) {
		c.pos += n
	}
}
func (c *cursor) bytes(n int) []byte {
	if !c.need(n) {
		return nil
	}
	v := c.b[c.pos : c.pos+n]
	c.pos += n
	return v
}
func (c *cursor) list16u16() []uint16 {
	total := int(c.u16())
	out := make([]uint16, 0, total/2)
	endp := c.pos + total
	for c.pos < endp && c.need(2) {
		out = append(out, c.u16())
	}
	return out
}

// ---------------------------------------------------------------------------
// HTTP handler: `ja4` directive — exposes the value to the pipeline
// ---------------------------------------------------------------------------

// Handler sets {http.vars.ja4} and (optionally) an upstream request header from
// the JA4 captured for this connection. It always overwrites any client-supplied
// value of Header, so a visitor cannot spoof it.
type Handler struct {
	// Header is the request header to set for the upstream (e.g. "X-JA4"). Optional.
	Header string `json:"header,omitempty"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.ja4",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ja4 := ""
	if v, ok := store.Load(r.RemoteAddr); ok {
		ja4, _ = v.(string)
	}
	caddyhttp.SetVar(r.Context(), "ja4", ja4)
	if h.Header != "" {
		if ja4 != "" {
			r.Header.Set(h.Header, ja4) // overwrite any client-supplied value
		} else {
			r.Header.Del(h.Header) // never let a visitor forge it
		}
	}
	return next.ServeHTTP(w, r)
}

// interface guards
var (
	_ caddy.ListenerWrapper       = (*ListenerWrapper)(nil)
	_ caddyfile.Unmarshaler       = (*ListenerWrapper)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

func parseHandlerCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var hh Handler
	for h.Next() {
		if h.NextArg() {
			hh.Header = h.Val()
		}
	}
	return hh, nil
}
