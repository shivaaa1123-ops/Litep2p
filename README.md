
# LiteP2P  
### Ultra‑fast, battery‑efficient P2P networking for Android & embedded devices  
![status](https://img.shields.io/badge/status-active-brightgreen)
![platform](https://img.shields.io/badge/platform-Android%20NDK-blue)
![language](https://img.shields.io/badge/language-C++20-orange)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## 🚀 Overview  
**LiteP2P** is a modern, lightweight peer‑to‑peer networking library written in C++ and optimized specifically for **Android performance, battery life, and reliability**.  
It provides all the essential building blocks for mobile‑friendly distributed applications without the heavy overhead of libp2p or JVM-based networking stacks.

LiteP2P is ideal for:
- Cross‑device sync  
- Metadata & thumbnail sharing  
- Distributed apps  
- High‑performance local & global connectivity  
- Apps that need low battery usage and tiny binaries  

---

## ✨ Key Features

### 🔥 High Performance Native Core  
- Epoll‑based asynchronous reactor  
- Zero-copy buffering & minimal allocations  
- No GC pauses, no JVM overhead  
- < 1 MB binary size  

### 🔒 Secure by Design  
- Ed25519 peer identity  
- Noise‑style encrypted channels (XChaCha20‑Poly1305)  
- Replay protection & authenticated handshake  

### 🌍 Global Connectivity  
- Direct TCP/UDP connections when possible  
- WebSocket fallback  
- Multiplexed relay support for NAT‑heavy networks  
- Bootstrap server optional but recommended  

### 📡 LAN Discovery  
- UDP broadcast  
- mDNS-compatible pattern  
- Instant pairing on the same WiFi or hotspot  

### 📁 Reliable File Transfer  
- Chunked transfer with resume  
- SHA‑256 integrity checks  
- Zero‑copy streaming  
- Works over direct or relay channels  

### 🪫 Battery‑Friendly  
- Single‑threaded epoll event loop  
- Adaptive keepalive intervals  
- Smart backpressure & congestion control  

---

## 🧱 Architecture Overview

```
+------------------------+       +-----------------------+
| Android App (Kotlin)  | <---> | LiteP2P (C++ Native)  |
|  - UI Layer           |  JNI  |  - Epoll Reactor      |
|  - ViewModel/Service  |       |  - Secure Framing     |
+------------------------+       |  - Discovery (UDP)    |
                                 |  - Relays (optional)  |
                                 +----------+------------+
                                            |
                                            v
                                    +---------------+
                                    |  Relay Server |
                                    |  (TCP/WS/TLS) |
                                    +---------------+
```

---

## 📦 Installation

### 1. Add to your Android project  
Place the LiteP2P source inside `app/src/main/cpp/litep2p/`.

### 2. Add CMake configuration

```cmake
add_library(litep2p SHARED
    litep2p.cpp
    epoll_reactor.cpp
)

target_link_libraries(litep2p
    android
    log
)
```

### 3. Enable NDK build in `build.gradle`

```gradle
android {
    externalNativeBuild {
        cmake {
            path "src/main/cpp/CMakeLists.txt"
        }
    }
}
```

### 4. Load library in Kotlin

```kotlin
init {
    System.loadLibrary("litep2p")
}
```

---

## 🧪 Quick Start Example

### Start a node

```kotlin
P2P.startServer(
    port = 4001,
    onMessage = { peer, type, data ->
        Log.d("LiteP2P", "Received message from $peer: $type")
    }
)
```

### Connect to a peer

```kotlin
P2P.connect("192.168.1.42", 4001)
```

### Send a message

```kotlin
P2P.sendMessage(peerId, "Hello from Android!".encodeToByteArray())
```

### Send a file

```kotlin
P2P.sendFile(peerId, File("/sdcard/DCIM/thumb.jxl"))
```

---

## 🌐 Optional Relay

LiteP2P works great on LAN, but for **global connectivity**, a relay server is recommended.

A minimal relay supports:
- TLS/WebSocket transport  
- Multiplexed data streams  
- Authentication tokens  
- Idle timeout management  

Relay reference implementation (Rust or C++) is coming soon.

---

## 📊 Roadmap

### v0.1  
- Core reactor  
- Framing + message types  
- File transfer + metadata  
- LAN discovery  

### v0.2  
- Encryption  
- Multiplexing  
- Relay protocol  

### v1.0  
- Complete SDK  
- Polished examples  
- Production relay cluster  

---

## 🤝 Contributing  
PRs are welcome! Please open an issue before submitting large changes.

---

## 📄 License  
**MIT License** — free to use in commercial or open-source projects.

---

## ❤️ Support / Contact  
For questions or feature requests, open an issue on GitHub.  
