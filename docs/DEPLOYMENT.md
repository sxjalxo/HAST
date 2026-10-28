# Deploying HAST

HAST is one binary on one port. It serves the web UI, the account API and both WebSockets, and keeps its state in
one directory (SQLite database plus two small files). Deploying it means: run the container, put a TLS proxy in
front, back up the data directory.

## 1. Run it

```bash
docker compose up -d --build
curl http://localhost:8000/health        # {"status":"healthy","uptime":...}
```

The image builds the UI and the server from source (Rust and Node only in the build stage) and runs on
`debian:stable-slim`. State lives in the `hast-data` volume, mounted at `/data`:

| file | contents |
|---|---|
| `/data/hast.db` (+ `-wal`, `-shm`) | accounts, password hashes, key chains, sessions, LiveChat history and messaging messages (ciphertext only) |

Files from older versions are imported into the database on first start and renamed: `/data/chat.jsonl` to
`chat.jsonl.imported`, and the messaging store `/data/messaging.json` to `messaging.json.imported`. Once imported, the
`.imported` files can be deleted.

Without Docker: build the UI (`cd crates/hast-web && trunk build --release`), build the server
(`cargo build --release -p hast-server`), and run `target/release/hast-server` with `HAST_STATIC_DIR` pointing at
`crates/hast-web/dist`. Run it under systemd or similar so it restarts.

## 2. Configure it

Set these in `docker-compose.yml` under `environment:`. The full list with defaults is in the
[README](../README.md#run).

| variable | production value |
|---|---|
| `HAST_COOKIE_SECURE` | `1` once the site is served over HTTPS (it must be, see below) |
| `HAST_SIGNUP` | `invite` with a long random `HAST_INVITE_CODE`, or `closed` after your users have signed up |
| `HAST_SESSION_DAYS` | `7` by default; lower it for shared machines |
| `HAST_ALLOWED_ORIGINS` | leave empty; only needed when the UI is served from another origin (development) |
| `HAST_TRUSTED_PROXIES` | the IP your reverse proxy connects from, e.g. `127.0.0.1` (see below) |
| `HAST_RP_ID` | your site's domain, e.g. `chat.example.org`, for passkeys. Passkeys are bound to it, so don't change it later |

## 3. Put TLS in front

The server speaks plain HTTP. Serve it through a reverse proxy that terminates TLS. The proxy must:

* forward the **`Host`** header unchanged: the server rejects POSTs and WebSocket upgrades whose `Origin` doesn't
  match `Host` (CSRF protection);
* set **`X-Forwarded-For`**, and list the proxy's address in `HAST_TRUSTED_PROXIES`, so login throttling and the
  signup limit see each client's IP instead of the proxy's;
* pass **WebSocket upgrades** for `/ws` and `/ws/messaging`, with a long read timeout;
* allow request bodies of about 1 MiB (signed messages and registrations are tens of KB).

nginx example:

```nginx
server {
    listen 443 ssl http2;
    server_name hast.example.com;

    ssl_certificate     /etc/letsencrypt/live/hast.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/hast.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 2m;

    location /ws {                      # matches /ws and /ws/messaging
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 1h;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}

server {
    listen 80;
    server_name hast.example.com;
    return 301 https://$host$request_uri;
}
```

Certificates: `sudo certbot certonly --nginx -d hast.example.com` (Let's Encrypt), or your provider's.

HAST sets its own Content-Security-Policy, `X-Frame-Options`, `X-Content-Type-Options` and `Referrer-Policy`, so the
proxy only needs to add HSTS. If you rebuild the UI outside Docker, restart the server: the CSP allows trunk's inline
loader by its hash, read from `index.html` at start.

When the proxy runs on the same host, publish the container port on loopback only (`"127.0.0.1:8000:8000"` in
`docker-compose.yml`) so nobody bypasses TLS.

**Client IPs behind a proxy:** the server throttles failed logins and signups by client IP. It takes that IP from
`X-Forwarded-For` only when the connection comes from an address in `HAST_TRUSTED_PROXIES`, and then uses the
right-most entry that isn't a trusted proxy (anything further left is client-supplied and could be forged). Without
the setting, every client behind the proxy shares the proxy's budget of 20 free failures; the per-name lockout works
either way.

With Docker, the proxy's address as the container sees it is usually the Docker bridge gateway (often `172.17.0.1`
or the compose network's gateway), not `127.0.0.1`; check with `docker network inspect`.

Rate limiting at the proxy is a useful extra layer:

```nginx
limit_req_zone $binary_remote_addr zone=hast_auth:10m rate=5r/m;
location ~ ^/api/(login|register|recover)$ {
    limit_req zone=hast_auth burst=10 nodelay;
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## 4. Operate it

Accounts (there is no email, so password resets go through the operator):

```bash
docker compose exec hast hast-server user list
printf '%s\n' 'new long password' | docker compose exec -T hast hast-server user reset alice
```

`reset` sets the password and ends all of that account's sessions. It doesn't touch the account's signing keys.

If someone lost every passkey on their account, remove them so the password signs in alone again (they can add new
ones on the Account page):

```bash
docker compose exec hast hast-server user passkeys-off alice
```

Logs: `docker compose logs -f hast`.

Upgrades:

```bash
git pull
docker compose up -d --build
```

Schema changes are numbered migration steps that run automatically on start (tracked in SQLite's `user_version`),
so an older database is upgraded in place. Back up first anyway (next section): migrations only go forward.

## 5. Back up

Everything is in `/data`. The simplest consistent backup stops the container briefly:

```bash
docker compose stop hast
docker run --rm -v hast_hast-data:/data -v "$PWD":/backup debian:stable-slim tar czf /backup/hast-$(date +%F).tgz -C /data .
docker compose start hast
```

The volume name is `<project>_hast-data`; check it with `docker volume ls`. Restore by extracting the archive
into an empty volume before starting the container.

Losing `hast.db` loses accounts and key chains. Users would have to sign up again, and their old messages would no
longer link to a verifiable chain. Private signing keys are never on the server, so a backup can't leak them;
it does contain Argon2id password hashes, so store it as sensitive.

## Production checklist

- [ ] Served only over HTTPS; HTTP redirects; container port bound to loopback or firewalled.
- [ ] `HAST_COOKIE_SECURE=1`.
- [ ] Proxy forwards `Host` and WebSocket upgrades (sign in, open `/chat`, send a message).
- [ ] Proxy sets `X-Forwarded-For` and its address is in `HAST_TRUSTED_PROXIES`.
- [ ] `HAST_SIGNUP` is `invite` or `closed`, and the invite code isn't the example value.
- [ ] `/health` monitored.
- [ ] Backups of `/data` scheduled, and a restore tested once.
- [ ] Someone knows how to run `hast-server user reset`.
