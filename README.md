# tds-caddy-ja4

A small, self-contained Caddy v2 module that computes the **base JA4 TLS client
fingerprint** at the edge (where the user's proxy terminates TLS) and exposes it
to the request pipeline as `{http.vars.ja4}` and an upstream request header.

- JA4 math is done by the vetted MIT library [`exaring/ja4plus`](https://github.com/exaring/ja4plus).
- **Only base JA4 (TLS)** is used — it is **BSD-3-Clause**, fine for commercial use.
  JA4+ variants (JA4H/JA4T/…) are intentionally NOT implemented (FoxIO License 1.1
  is *not* permissive for monetization).
- Fails open: if anything goes wrong, JA4 is empty and the request proceeds.

## Why

In our topology `visitor → user's Caddy proxy → main nginx`, TLS terminates at the
user's proxy. That is the **only** place the visitor's ClientHello exists, so JA4
must be computed there and forwarded to the main server as a header. The main
server then does cross-layer validation: *UA claims Chrome but JA4 is a Go/curl/
python stack → bot*.

## Build

```bash
xcaddy build --with github.com/TDS-SO/caddy-ja4
caddy list-modules | grep -E 'caddy.listeners.ja4|http.handlers.ja4'   # verify
```

Put this directory in its own repo (`github.com/TDS-SO/caddy-ja4`) and pin a
reviewed tag. Build the binary **once** on your CI, host it yourself, and have the
installer download it (do NOT run `xcaddy`/fetch from GitHub on the user's VPS at
install time).

> Build status: this module **compiles and `go vet`s clean** against Caddy v2.9.1
> and ja4plus v0.0.3. It has **not** been runtime-tested — validate on a staging
> proxy (real browser handshake → correct JA4, handshake not broken) before fleet
> rollout.

## Caddyfile

```caddyfile
{
    order ja4 before reverse_proxy        # run the handler before proxying
    servers {
        listener_wrappers {
            ja4                            # MUST be before tls
            tls
        }
    }
}

example.com {
    ja4 X-JA4                              # sets {http.vars.ja4} and the X-JA4 request header
    reverse_proxy 127.0.0.1:8080 {
        header_up X-JA4 {http.vars.ja4}    # (redundant with `ja4 X-JA4`, explicit is fine)
        header_up X-Real-IP {client_ip}
        # ...your existing header_up lines...
    }
}
```

- `ja4 X-JA4` overwrites any client-supplied `X-JA4` (and deletes it when no JA4 is
  available), so a visitor cannot spoof the header.
- Without the JA4-enabled binary, the `listener_wrappers { ja4 }` line makes stock
  Caddy fail to start — so the **installer must add the JA4 config only when the
  JA4 binary is confirmed** (`caddy list-modules | grep -q caddy.listeners.ja4`),
  and otherwise write the Caddyfile exactly as today (graceful fallback, no JA4).

## Backend usage

The upstream receives the fingerprint in the `X-JA4` request header (empty when
unavailable, so handle its absence gracefully). Treat it as one signal among others:

- **Cross-layer check** — if the User-Agent claims a major browser but the JA4
  matches a known HTTP-library / automation TLS stack, the client is likely a bot.
- **Grouping key** — aggregate traffic and reputation per JA4 rather than blocking
  on a single value.

A single JA4 can be spoofed (e.g. curl-impersonate, uTLS), so combine it with other
signals instead of using it as a hard block.
