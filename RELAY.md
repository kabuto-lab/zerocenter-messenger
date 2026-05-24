# ME55 — Bootstrap + Relay setup

Two ME55 nodes behind NAT can't find each other on the open internet
without help. They need:

1. **A bootstrap node** so Kademlia DHT discovery works (otherwise
   neither node ever joins the DHT and they can't be looked up).
2. **A relay node** so the actual connection can be proxied through a
   public peer when direct TCP between the two NATs isn't possible.
   After relay-connect succeeds, DCUtR tries to upgrade to a direct
   connection — if hole-punching works, the relay drops out of the
   path; if not, traffic keeps going through the relay.

The same VPS / always-on machine can serve **both** roles. One process,
one CLI invocation.

---

## Running a public bootstrap+relay node

Requirements: any always-on machine with a **publicly reachable
IPv4/IPv6 address** (or a UDP/TCP port forwarded from a NAT router).

Concrete example — cheap VPS (Hetzner CX11 / Vultr / DO droplet, ~$4-6/mo):

```bash
# 1. SSH into the VPS, install Rust (one-time)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 2. Clone + build the headless binary (no GUI feature needed)
git clone https://github.com/<your-org>/ME55-messenger.git
cd ME55-messenger
cargo build --release            # produces target/release/ME55

# 3. Open TCP port 4001 in the firewall
sudo ufw allow 4001/tcp          # (Ubuntu)

# 4. Run on a fixed port + enable the relay-server role
./target/release/ME55 \
    --profile relay-server \
    --port 4001 \
    --relay-server
```

The node prints its `Peer ID: 12D3KooW…` on startup. Combined with the
VPS public IP, the dial-able multiaddr is:

```
/ip4/<VPS_PUBLIC_IP>/tcp/4001/p2p/12D3KooW…
```

Distribute this string to anyone who wants to use this node as
bootstrap+relay.

---

## Connecting from a NAT'd client

On any peer behind NAT (a regular laptop on home WiFi), launch:

```bash
ME55AGUI.exe \
    --profile alice \
    --bootstrap /ip4/<VPS_IP>/tcp/4001/p2p/12D3KooW... \
    --relay     /ip4/<VPS_IP>/tcp/4001/p2p/12D3KooW...
```

- `--bootstrap` seeds the Kademlia DHT so the client can find other
  peers by PeerId.
- `--relay` registers a circuit-relay listener at
  `…/p2p/<RelayId>/p2p-circuit`, so other peers (also bootstrapped via
  the same relay) can dial this client through the relay.

Both flags can repeat: `--bootstrap addr1 --bootstrap addr2 --relay addr1`.
If you trust multiple public nodes, list them all and the network is
resilient to any single one dropping out.

---

## Two-peers-via-relay test recipe

Computer A (Alice, behind NAT) and Computer B (Bob, behind a DIFFERENT
NAT). Both run:

```bash
# Alice
ME55AGUI.exe --profile alice \
    --bootstrap /ip4/<RELAY_IP>/tcp/4001/p2p/<RELAY_PID> \
    --relay     /ip4/<RELAY_IP>/tcp/4001/p2p/<RELAY_PID>

# Bob
ME55AGUI.exe --profile bob \
    --bootstrap /ip4/<RELAY_IP>/tcp/4001/p2p/<RELAY_PID> \
    --relay     /ip4/<RELAY_IP>/tcp/4001/p2p/<RELAY_PID>
```

What happens:

1. Both clients dial the relay → relay accepts circuit reservation,
   each client now has an addressable `/p2p/<RelayId>/p2p-circuit/p2p/<self>`.
2. Both clients join the Kademlia DHT via the relay (which acts as
   bootstrap peer).
3. Alice asks the DHT for Bob's PeerId → DHT returns Bob's relayed
   multiaddr.
4. Alice dials Bob through the relay → connection established (Noise
   handshake completes over the circuit).
5. DCUtR fires: both peers learn each other's observed public IP:port
   from the relay, attempt simultaneous TCP open. If their NATs allow
   it → direct connection takes over. If not → traffic stays on the relay.

In `RUST_LOG=debug` you'll see `DCUtR event: …` lines on both sides
when upgrade succeeds.

---

## Local testing (no VPS)

To smoke-test the wiring on one machine, run three processes in
three terminals:

```bash
# Terminal 1 — the relay node (port 4001)
./target/release/ME55 --profile relay-server --port 4001 --relay-server --cli
# note the printed Peer ID — call it $RELAY_PID

# Terminal 2 — Alice (port 0 = random)
./target/release/ME55 --profile alice --cli \
    --bootstrap /ip4/127.0.0.1/tcp/4001/p2p/$RELAY_PID \
    --relay     /ip4/127.0.0.1/tcp/4001/p2p/$RELAY_PID

# Terminal 3 — Bob (port 0 = random)
./target/release/ME55 --profile bob --cli \
    --bootstrap /ip4/127.0.0.1/tcp/4001/p2p/$RELAY_PID \
    --relay     /ip4/127.0.0.1/tcp/4001/p2p/$RELAY_PID
```

In Alice's window: `send <Bob's PeerId> hi`. Bob receives. If you stop
the relay, ratchet state persists, but new sessions can't bootstrap
until the relay (or another) comes back.

---

## What about `--obfs-key`?

`--obfs-key` wraps the **direct** TCP transport in ChaCha20-keystream
XOR (ScrambleStream). It does **not** affect relayed connections —
when bytes go through a third-party relay, we can't have a scramble
layer between us and them (the relay would have to decrypt it). So
relayed traffic uses plain libp2p Noise, while direct
DCUtR-upgraded traffic gets the scramble wrapper.

For maximal obfuscation, run with both flags — direct connections
between client peers will be scrambled; the initial relay-mediated
contact will be plain libp2p; once DCUtR upgrades to direct, scramble
kicks in.

---

## Limitations of v0

- **Single bootstrap+relay node** is a single point of failure for
  initial contact. Once peers have established a session, they can
  reconnect without the relay (cached multiaddr in the contact). Run
  multiple relays for redundancy.
- **DCUtR doesn't always succeed.** Symmetric NATs and CGNAT can
  defeat hole punching; traffic stays on the relay (uses your relay
  bandwidth indefinitely).
- **No relay discovery via DHT yet.** Clients must be told relay
  multiaddrs explicitly via `--relay`. Auto-discovery from DHT
  records is a Phase 6 candidate.
- **No relay reputation / rate-limiting.** The relay-server accepts
  reservations from anyone; abuse-resistance is unlikely to matter
  at v0 scale but will need attention before broad release.
