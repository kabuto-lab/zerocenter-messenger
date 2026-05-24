# Beget VPS — bootstrap+relay node setup

End-to-end checklist for turning your Beget VPS into `bootstrap-1` of the
ME55 public bootstrap network. After this is done and you've sent me the
node's **public IP + PeerId**, I'll bake the multiaddr into
`DEFAULT_BOOTSTRAPS` and rebuild the binaries so every ME55 install will
auto-connect to your node.

Time estimate: **30-45 minutes** end-to-end if you've used SSH before;
~60-90 minutes for first-time Linux work.

---

## Step 0 — Beget VPS prep

In the Beget control panel:
1. Confirm the VPS is **Ubuntu 22.04 LTS** (or 20.04 / Debian 12; instructions assume Ubuntu 22.04).
2. Note the **public IPv4 address** (e.g. `85.x.x.x`) and **root password** (or SSH key).
3. In the firewall section of the Beget control panel, **allow inbound TCP 4001**.
   - If Beget exposes a separate firewall layer beyond `ufw`, both layers must allow 4001.

---

## Step 1 — SSH in + system update

From your local machine:

```bash
ssh root@<BEGET_PUBLIC_IP>
```

On the VPS:

```bash
apt update && apt upgrade -y
apt install -y curl build-essential pkg-config libssl-dev git ufw
```

---

## Step 2 — Install Rust toolchain

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
source "$HOME/.cargo/env"
rustc --version    # confirm: 1.75+ recommended
```

The default install path is `~/.cargo`. About 1.5 GB needed.

---

## Step 3 — Clone + build ME55 (headless, no GUI)

```bash
cd /opt
git clone https://github.com/kabuto-lab/zerocenter-messenger.git me55
cd me55
cargo build --release    # ~5-10 minutes on a low-end VPS
```

Artifact: `/opt/me55/target/release/ME55` (Linux ELF, ~10 MB).

> **Note:** the GitHub repo URL above uses the pre-rebrand name. If you
> renamed the repo on GitHub after the local rebrand, substitute the new
> URL. The build artifact is `ME55` either way because the Cargo `[[bin]]`
> name was renamed in the rebrand commit.

---

## Step 4 — Dedicated user + filesystem layout

```bash
useradd -r -s /sbin/nologin -m -d /var/lib/me55 me55
install -d -o me55 -g me55 -m 700 /var/lib/me55
ln -sf /opt/me55/target/release/ME55 /usr/local/bin/ME55
```

The `me55` user has no shell and no home that ME55 can be tricked into
escaping into. The binary lives in `/opt/me55/` (rebuildable), the data
directory lives in `/var/lib/me55/` (owned by `me55`).

---

## Step 5 — Firewall

```bash
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 4001/tcp
ufw --force enable
ufw status verbose
```

Confirm output shows `4001/tcp ALLOW`.

---

## Step 6 — systemd unit

Create `/etc/systemd/system/me55-relay.service`:

```ini
[Unit]
Description=ME55 bootstrap + relay node
Documentation=https://github.com/kabuto-lab/zerocenter-messenger
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=me55
Group=me55
Environment=HOME=/var/lib/me55
Environment=XDG_DATA_HOME=/var/lib/me55
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/ME55 --profile relayhost --port 4001 --relay-server --daemon --no-default-bootstrap

Restart=always
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# Resource limits
MemoryMax=512M
CPUQuota=80%
TasksMax=512

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/me55
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=

StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

`--no-default-bootstrap` is intentional on a public relay: this node
should not loop-dial itself via its own future hardcoded address. It
operates as a pure standalone seed for inbound connections.

Activate:

```bash
systemctl daemon-reload
systemctl enable --now me55-relay.service
sleep 5
systemctl status me55-relay.service       # confirm "active (running)"
journalctl -u me55-relay.service --no-pager | tail -30
```

---

## Step 7 — Grab the PeerId

The first log lines tell you the PeerId — it's deterministic from the
ed25519 keypair, which got generated on first startup and persists in
`/var/lib/me55/.local/share/ME55/relayhost/identity.json` (path depends
on the systemd `XDG_DATA_HOME` override; check `find /var/lib/me55 -name
identity.json` if needed).

```bash
journalctl -u me55-relay.service --no-pager | grep "Peer ID:"
# expect a single line like:
#   Peer ID: 12D3KooWXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX...
```

Copy that PeerId. Combine with the Beget public IP into the full multiaddr:

```
/ip4/<BEGET_PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>
```

---

## Step 8 — Smoke-test from your laptop

Back on your Windows laptop, with `ME55AGUI.exe` already built:

```cmd
ME55AGUI.exe --profile probe --bootstrap /ip4/<BEGET_PUBLIC_IP>/tcp/4001/p2p/<PEER_ID> --relay /ip4/<BEGET_PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>
```

In the GUI window or in the logs you should see:

```
Seeding 1 bootstrap candidate(s)
Seeded Kademlia with bootstrap peer 12D3KooW... at /ip4/<BEGET_IP>/tcp/4001/p2p/12D3KooW...
Dialing relay 12D3KooW... at /ip4/<BEGET_IP>/tcp/4001/p2p/12D3KooW...
Listening on circuit-relay: /ip4/<BEGET_IP>/tcp/4001/p2p/12D3KooW.../p2p-circuit
Connected to: 12D3KooW... via Dialer { ... }
```

On the Beget side (`journalctl -u me55-relay.service -f`) you should see
the matching `Connected to:` + `Identify from:` lines.

---

## Step 9 — Send me

Once Step 8 prints "Connected", send me:

1. **Multiaddr**: `/ip4/<BEGET_PUBLIC_IP>/tcp/4001/p2p/<PEER_ID>`
2. (Optional) A friendly name / region tag for the manifest, e.g. `"RU-msk"` or `"bootstrap-1"`.

I will:
- Update `DEFAULT_BOOTSTRAPS` in `src/network/bootstrap.rs` to include this multiaddr
- Rebuild the binaries
- From then on, every fresh `ME55AGUI.exe` will auto-connect to your Beget node out of the box — that's the "install and works" property
- The PEX cache will spread your node further: any peer that successfully connects through Beget gets your multiaddr in their local cache, so even if Beget goes down later they can keep talking to peers they've already met

---

## Maintenance commands

```bash
# Tail logs in real time
journalctl -u me55-relay.service -f

# Restart (after pulling new code + rebuild)
cd /opt/me55 && git pull && cargo build --release
systemctl restart me55-relay.service

# Stop temporarily
systemctl stop me55-relay.service

# Check resource usage
systemctl status me55-relay.service
# Look at the "Memory:" and "Tasks:" lines.

# Verify firewall hasn't drifted
ufw status verbose
```

---

## Threat-model reminder

Your Beget VPS will see **passive metadata** of every peer that connects
through it as bootstrap or relay:
- Source IP of connecting peers
- Peer IDs they advertise
- Timing of connections
- Bytes transferred (volume, not content — content stays E2E)

It will **not** see message content (that's ratchet-encrypted end-to-end
between peers). But this metadata leak is jurisdictionally interesting:
Beget is a Russian provider, and a compelled-logs scenario means the FSB
could enumerate ME55 users connecting through your Beget node.

This is why the v1 plan calls for **at least 2 more bootstrap nodes**
outside Russia (Oracle Cloud Free in US-East and EU-Frankfurt). Your
Beget node is `bootstrap-1`; we want at least `bootstrap-2` and
`bootstrap-3` in different jurisdictions before announcing the network.
Users in adversarial environments can use `--no-default-bootstrap` and
manually configure their own.
