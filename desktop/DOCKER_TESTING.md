# Docker + multi-peer testing

This repo’s discovery uses **UDP broadcast** on port **30000** and advertises the peer’s reachable address as `<sender_ip>:<peer_port>`.

That means:
- If peers can **broadcast to each other** and the advertised `sender_ip` is **reachable**, they’ll show up in `peers` and you can `connect <id-prefix>`.
- If the advertised `sender_ip` is **not reachable** (common with Docker Desktop on macOS), discovery may still “see” peers but connections won’t work.

## Reality check: “bridge mode gets a Wi‑Fi IP”

### Docker Desktop on macOS
Docker Desktop runs containers inside a Linux VM. Containers get an IP *inside that VM’s NAT*, not a unique IP on your Wi‑Fi LAN.

So on macOS you generally **cannot** make a container obtain a true unique LAN IP from Wi‑Fi via Docker “bridge mode”. (macvlan/ipvlan-style “real LAN IP per container” is a **Linux host** feature.)

### What works instead
- Run Linux peers **on a real Linux host** (or a Linux VM with bridged networking).
- For cross-platform tests, run:
  - macOS peer on the mac host, and
  - Linux peers on a Linux host using either **host networking** or **macvlan/ipvlan**.

## A) Two Linux peers in Docker (Linux host)

### Option A1: user-defined bridge (containers get unique 172.x IPs)
Best for **Linux↔Linux in Docker** testing.

1) On the Linux host, create an image containing the runtime deps + binary:

```bash
mkdir -p /tmp/litep2p_docker && cd /tmp/litep2p_docker
cp /path/to/litep2p_peer_linux ./litep2p_peer_linux
cp /path/to/config.json ./config.json

cat > Dockerfile <<'EOF'
FROM ubuntu:22.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libsodium23 libuuid1 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY litep2p_peer_linux /app/litep2p_peer
COPY config.json /app/config.json
ENTRYPOINT ["/app/litep2p_peer","--config","/app/config.json"]
EOF

docker build -t litep2p-peer:local .
```

2) Create a dedicated Docker network:

```bash
docker network create litep2pnet
```

3) Run two peers (use 2 terminals):

```bash
docker run --rm -it --name p1 --network litep2pnet litep2p-peer:local \
  --id linux1 --port 30001 --log-level info
```

```bash
docker run --rm -it --name p2 --network litep2pnet litep2p-peer:local \
  --id linux2 --port 30001 --log-level info
```

4) In either peer’s CLI:
- `peers`
- `connect <id-prefix>`
- `send <id-prefix> hello`

### Option A2: host networking (no container IPs; uses host IP + different ports)
Best when you want the peers to be reachable from **outside Docker** (e.g., from your macOS host on the LAN).

```bash
docker run --rm -it --network host litep2p-peer:local \
  --id linux1 --port 31001 --log-level info
```

```bash
docker run --rm -it --network host litep2p-peer:local \
  --id linux2 --port 31002 --log-level info
```

Notes:
- Both instances still bind discovery port **30000/udp**; the discovery socket uses reuse options and should coexist.
- Because they share the host IP, they must have **different** `--port` values.

## B) Cross-platform: macOS peer ↔ Linux peer(s)

### Recommended setup
- Run the macOS peer natively on macOS.
- Run the Linux peer(s) on a Linux host:
  - either natively, or
  - in Docker with `--network host` or macvlan/ipvlan.

On macOS:

```bash
./desktop/build_mac/bin/litep2p_peer_mac --id macA --port 30001 --log-level info
```

On the Linux host (native run):

```bash
./litep2p_peer_linux --id linuxB --port 30001 --log-level info
```

Or on the Linux host (Docker, host network):

```bash
docker run --rm -it --network host litep2p-peer:local \
  --id linuxB --port 30001 --log-level info
```

Then in either UI:
- `peers`
- `connect <id-prefix>`
- `send <id-prefix> hello cross-platform`

## C) “Unique LAN IP per container” (Linux host only; advanced)

If you truly need each container to appear as a separate device on your Wi‑Fi/LAN, you want **macvlan** (or sometimes **ipvlan**).

Example (adjust `parent`, `subnet`, `gateway`):

```bash
docker network create -d macvlan \
  --subnet=192.168.1.0/24 --gateway=192.168.1.1 \
  -o parent=wlan0 litep2p-macvlan
```

Run a peer on that LAN network:

```bash
docker run --rm -it --network litep2p-macvlan litep2p-peer:local \
  --id linux1 --port 30001 --log-level info
```

Important caveats:
- Many Wi‑Fi APs/drivers block multiple MACs behind one client; macvlan may fail on some Wi‑Fi setups.
- By default, the Linux host cannot talk to its own macvlan containers; you may need a host-side macvlan interface if you want host↔container traffic.

## D) Docker Desktop on macOS: what you *can* test

On macOS, Docker is still useful to:
- build the Linux binary, and
- run a Linux peer process for basic smoke tests.

But for LAN broadcast discovery and realistic peer connectivity, use a Linux host/VM or the built-in signaling/TURN configuration.
