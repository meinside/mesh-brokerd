# Deployment Guide (`brokerd` hosting)

Guidance on where to deploy `brokerd` (the mochi-mqtt-embedded broker +
storage + monitoring process). The architecture is designed not to depend
on any specific hosting method — whichever path below you pick,
`brokerd`'s own implementation/configuration stays the same. The only
difference is how you obtain a public domain/TLS/firewall.

## Common requirements (regardless of hosting method)

1. **A public domain, or a stable public IP**
2. **TLS**: certificate issuance/renewal via a standard method (e.g. Let's
   Encrypt/`certbot`)
3. **Firewall — expose exactly these, nothing more**:
   - `8883` (MQTT over TLS): the standard IANA-assigned port for
     MQTT+TLS. Meshtastic's `mqtt.address` accepts an explicit `host:port`
     (confirmed in `src/mqtt/MQTT.cpp`'s `parseHostAndPort`) and otherwise
     defaults to `1883` for plaintext or `8883` when
     `mqtt.tls_enabled=true` — so using the standard port needs no special
     board-side configuration. **`brokerd` binds this one itself.**
   - Whatever port your reverse proxy serves the monitoring API on
     (`80`/`443`, depending on how TLS is terminated). `brokerd` does
     **not** bind this: it listens on `127.0.0.1` only and the proxy
     publishes it — see §"Monitoring API behind a reverse proxy" below and
     `docs/monitoring-api.md` §0.
   - `80` (HTTP): also needed if using the ACME **HTTP-01** challenge type
     for certificate issuance/renewal. Using the **DNS-01** challenge type
     instead (ADR-8, what this project does) avoids needing port 80 for
     certificates at all.
   - **Do not expose admin/configuration-changing functionality on a
     public port at all.** Only the read-only monitoring API is published;
     any endpoint that can change `brokerd`'s configuration should be
     reachable only through an SSH tunnel or an IP allowlist restricted to
     a management network (see `docs/security.md` §4).
4. **Strong authentication**: accounts/ACL/hashed passwords/failure
   monitoring hooks from `docs/security.md`
5. **`systemd` registration**: `Restart=always` for automatic recovery
   from crashes. A ready-to-install unit file lives at
   `deploy/mesh-brokerd.service` — see §"systemd unit" below for what it does
   and the two things to verify on first start.

## Path A: a public VPS/server (default, recommended)

If you already have a public Linux server you can operate, use this as the
default path.

1. Deploy the `brokerd` binary on the server (register as a `systemd`
   service).
2. Point a domain at the server's public IP (A/AAAA record).
3. TLS certificate: `brokerd` manages this itself via an in-process
   ACME DNS-01 client (`internal/tlscert`, ADR-8) — no separate
   `certbot`/cron step, and port `80` never needs to be opened.
4. Open `8883` plus whatever port the reverse proxy uses for the
   monitoring API in the firewall (`ufw`/cloud security group) — see the
   firewall list under "Common requirements" above.
5. Both boards connect **symmetrically** to this server's domain
   (`mqtt.address = <domain>:8883`, `mqtt.tls_enabled = true`).

**Pros**: a standard approach (plenty of documentation/community
resources), unaffected by home power/internet outages, both sites are
fully symmetric.
**Trade-off**: the home board also becomes exposed to its own site's
internet outages (previously it could fall back to a local home-lab
broker). There may be separate server cost/maintenance (though none if
using a server you already operate).

## Path B: exposing a home lab (alternative)

If you'd rather run `brokerd` on a home-lab device (e.g. an RPi5), use one
of the two sub-approaches below to make it publicly reachable.

### B-1. Port forwarding + DDNS + certbot (the traditional approach)

- Forward the port(s) `brokerd` uses on your router to the home-lab
  device.
- If you don't have a static IP, keep a domain updated via DDNS (e.g.
  Cloudflare, No-IP).
- Issue a TLS certificate via `certbot`.
- **Caution**: this method **exposes your home router/network directly to
  the internet.** Forward nothing beyond the port(s) `brokerd` actually
  uses, and separately confirm the router's own admin interface is not
  exposed externally.

### B-2. Tailscale Funnel (a previously used design, still a valid alternative)

- Use Tailscale Funnel's `tls-terminated-tcp` mode to expose the home-lab
  device's local port publicly. This avoids exposing the router directly.
- Constraints: only ports 443/8443/10000 can be made public, it's a beta
  feature, bandwidth is limited, and it may require enabling Funnel
  explicitly in the admin console (unverified).
- If this path is actually chosen, fill in the concrete steps here at that
  time (or refer to Tailscale's official documentation in the meantime).

### Special-casing the home board under Path B (optional)

If `brokerd` runs from a home lab, the home board doesn't have to go
through the internet at all — it can **connect directly over the local
LAN** (`mqtt.address = <home-lab local IP>`, no TLS needed). This restores
the benefit of the home board staying able to talk to `brokerd` locally
even during a home internet outage (though cross-site relay still depends
on `brokerd`'s own internet connectivity).

## Choosing a path

| Situation | Recommended path |
|---|---|
| You already have a public server you can operate | A (default) |
| No public server, only a home lab, and exposing the router is acceptable | B-1 |
| No public server, only a home lab, and you want to avoid exposing the router | B-2 |
| You want the home board to keep working locally during a home internet outage | B (B-1 or B-2) + "special-casing the home board" |

## systemd unit

`deploy/mesh-brokerd.service` in this repository is the
version-controlled **template**. systemd does not read it from there — it
has to be copied to `/etc/systemd/system/mesh-brokerd.service`,
which is the standard location for units an administrator installs by
hand (and takes precedence over `/usr/lib/systemd/system/`, where distro
packages put theirs). That copy step needs root:

```bash
sudo cp deploy/mesh-brokerd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mesh-brokerd
```

After editing the template later, re-copy it and run
`sudo systemctl daemon-reload` again — editing the repo file alone
changes nothing about the running service.

> A **user** unit (`~/.config/systemd/user/`, managed with
> `systemctl --user`, no root needed) is not usable here:
> `AmbientCapabilities=CAP_NET_BIND_SERVICE` only takes effect for system
> units, and user units do not start at boot unless lingering is enabled
> (`loginctl enable-linger`). Since the point of the unit is surviving
> reboots, it must be a system unit. (The capability argument no longer
> applies now that the monitoring API binds loopback rather than `:443`,
> but the boot-persistence one still does.)

Why it matters: `brokerd` is the system's single point of failure and
messages lost during an outage **cannot be recovered afterwards**
(`docs/architecture.md` §7). Running it unsupervised (e.g. a backgrounded
`nohup` process) means a server reboot silently ends all cross-site
bridging with no recovery, so supervision is not optional for real use.

Two things the unit does that are easy to miss:

- **No capabilities are granted** (`CapabilityBoundingSet=` is empty).
  Earlier revisions needed `AmbientCapabilities=CAP_NET_BIND_SERVICE` so
  the monitoring listener could bind `:443`; now that it binds loopback
  and a reverse proxy publishes it, no privileged port is involved.
- **`KillSignal=SIGTERM` + `TimeoutStopSec=30`** gives ADR-6's graceful
  shutdown (drain the storage queue, then exit) time to finish before
  systemd escalates to `SIGKILL`.

### Verify on first start

⚠️ **`EnvironmentFile` and `$` in bcrypt hashes.** Values in `.env` must
be **single-quoted** (`KEY='value'`). A bcrypt hash contains `$`
characters (`$2a$12$...`), and an unquoted value is subject to variable
expansion by anything shell-like that reads the file — this project hit
exactly that bug during its first integration test (a `source .env` in
bash silently truncated the hash to a few characters, producing
authentication failures that looked like a wrong password). systemd's
`EnvironmentFile` strips matching quotes and does not expand variables,
but **this has not been verified end-to-end on this deployment**, so
check it explicitly:

```bash
systemctl status mesh-brokerd --no-pager
journalctl -u mesh-brokerd -n 50 --no-pager
```

Expected on a healthy start:
- **no** `bind: permission denied` for the monitoring listener
- once a board connects, **no** `auth: rejected` lines from
  `brokerd-bcrypt-auth`

If boards get `auth: rejected (unknown username or wrong password)`
after switching to systemd while they authenticated fine before, suspect
the `.env` quoting first, not the board.

If the service fails to start at all, the sandboxing directives
(`ProtectSystem=strict`, `ProtectHome=read-only`, `ReadWritePaths=`) are
the most likely cause — comment out the hardening block, confirm it
starts, then re-add the directives one at a time. `brokerd` only needs
write access to `storage.path`'s directory (which also holds the
SQLite `-wal`/`-shm` files and `listener.tls_cache_dir`).

## Monitoring API behind a reverse proxy

`brokerd` binds the monitoring API to `127.0.0.1` only and does not
publish it (`docs/monitoring-api.md` §0). Exposing it is a reverse-proxy
job; `deploy/nginx/monitoring-site.conf.sample` is the site template,
proxying a hostname to `127.0.0.1:9101`.

Hardening the nginx instance itself — restoring the real client IP behind
Cloudflare, claiming a catch-all `default_server`, and refusing requests
that did not arrive through Cloudflare — is server-wide configuration
shared with every other site on the machine, so it is deliberately out of
scope for this repository.

One consequence is worth recording because it is specific to this
deployment: the MQTT hostname must stay **DNS-only** (Cloudflare's HTTP
proxy cannot carry arbitrary TCP, and Spectrum is Enterprise-only), so the
origin IP is published in DNS. This deployment therefore does not get the
origin-IP obscurity a fully proxied site enjoys, and anyone can address
the origin directly. Restricting nginx to Cloudflare's ranges is what
closes that path, and it was verified against this deployment rather than
assumed.

