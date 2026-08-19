# Mobile-First Decentralized Network OS SDK

## Detailed Architecture, Protocol Evolution, and Implementation Roadmap

**Status:** Architecture and implementation guidance\
**Primary target:** Android / mobile devices\
**Core implementation:** C++\
**Design goal:** A general-purpose, reliable, resource-efficient
decentralized network runtime that can serve many applications, with
ChatP2P/EDP as the first major workload.

------------------------------------------------------------------------

## 1. Executive Direction

The current ChatP2P EDP proposal is a strong starting point for
decentralized store-and-forward delivery. It already identifies several
important properties: sender-independent delivery, redundant carrier
copies, fixed TTL, delivery receipts, bounded storage, deduplication,
serverless presence, and honest failure reporting.

However, the long-term SDK should **not become a messaging SDK with
increasingly complicated mailbox features**.

The recommended direction is to turn the existing C++ SDK into a
**mobile-first network runtime** whose fundamental abstraction is a
durable network object:

> **A network object can survive the disappearance of its creator and
> can be securely stored, replicated, routed, delivered, acknowledged,
> and expired by the network according to policy.**

Chat messages then become one application of this runtime. The same
substrate should later support files, IoT commands, telemetry,
synchronization records, distributed caches, software updates, backup
metadata, media manifests, and other application-defined objects.

The architecture should optimize for the constraints of phones from the
beginning:

-   minimal wakeups;
-   minimal background CPU;
-   minimal radio activation;
-   bounded RAM;
-   bounded persistent storage;
-   small control packets;
-   adaptive replication instead of constant flooding;
-   batching whenever latency requirements allow it;
-   no assumption that an Android process remains alive;
-   durable crash recovery;
-   opportunistic operation under Doze and background restrictions;
-   optional infrastructure rather than mandatory infrastructure;
-   reliability based on persistence, replication, reconciliation, and
    cryptographic confirmation rather than permanent processes.

The goal should be **"no mandatory server"**, not "servers are
forbidden." Bootstrap nodes, relays, NAT traversal infrastructure,
enterprise gateways, or rendezvous services can improve reachability
while remaining optional.

------------------------------------------------------------------------

# 2. Product Definition: What the SDK Should Become

The SDK should eventually look conceptually like this:

``` text
                     Applications
       ┌───────────────┼────────────────┐
       │               │                │
     Chat            Files             IoT
       │               │                │
       └───────────────┼────────────────┘
                       │
              Application Network API
                       │
┌─────────────────────────────────────────────────────────┐
│                  NETWORK RUNTIME CORE                   │
│                                                         │
│ Identity / Trust                                        │
│ Secure Sessions                                         │
│ Discovery                                               │
│ Connection Management                                   │
│ Object Store                                            │
│ Routing / Peer Selection                                │
│ Replication / Anti-Entropy                              │
│ Store-and-Forward Delivery                              │
│ Receipts / Delivery State                               │
│ Resource / Battery / Quota Manager                      │
│ Abuse Protection                                        │
│ Persistence / Crash Recovery                            │
│ Scheduler                                               │
│ Observability                                           │
└────────────────────────┬────────────────────────────────┘
                         │
                 Transport Abstraction
       ┌─────────────────┼─────────────────┐
       │                 │                 │
      QUIC              TCP               UDP
       │
  LAN / Wi-Fi / BLE / Wi-Fi Direct / Relay
```

The runtime should be usable without ChatP2P and without
Android-specific application logic.

------------------------------------------------------------------------

# 3. Design Principles

## 3.1 Mobile first, not desktop code ported to Android

Every subsystem must assume:

-   processes can be killed;
-   connectivity changes constantly;
-   IP addresses change;
-   NAT is normal;
-   the device sleeps;
-   background execution is restricted;
-   battery is more valuable than a small reduction in latency;
-   radio wakeups are expensive;
-   storage is finite;
-   peers appear and disappear unpredictably.

Reliability must therefore come primarily from **durable state and
protocol design**, not from keeping threads alive indefinitely.

## 3.2 Durable before fast

A successful API return must have a precise meaning.

For example:

``` text
QUEUED_LOCAL
    = durably persisted locally

ACCEPTED_REMOTE
    = at least one remote storage peer confirmed persistence

REPLICATED
    = requested durability target reached

DELIVERED
    = destination accepted the object

CONFIRMED
    = cryptographically verifiable destination receipt obtained
```

The application must never confuse "socket write succeeded" with
"message is safely in the network."

## 3.3 Policy instead of hardcoded behavior

Do not hardcode `F=3`, `R=2`, `TTL=48h`, and `maxHops=4` into the
engine.

Expose a delivery policy and let the runtime choose an efficient
execution plan.

## 3.4 No mandatory central dependency

The network should continue operating in connected components if all
optional infrastructure disappears.

## 3.5 Bounded everything

Every queue, cache, database table, retry mechanism, peer table, pending
handshake, message size, gossip operation, and timer must have an
explicit bound.

This is essential on Android.

## 3.6 Event-driven, not polling-driven

Avoid periodic 5-second/10-second/20-minute loops when a network,
lifecycle, discovery, WorkManager, alarm, connectivity, or peer-session
event can trigger the same work.

## 3.7 Batch work

When the phone is awake and the radio is already active, perform useful
reconciliation in one batch rather than waking the device repeatedly.

## 3.8 Idempotent operations

A crash or retry must be safe at every protocol step.

------------------------------------------------------------------------

# 4. Fundamental Abstraction: Network Object

Replace a messaging-specific internal model with a generic object.

A conceptual definition:

``` cpp
struct NetworkObjectHeader {
    ProtocolVersion protocol_version;

    NetworkId network_id;
    NamespaceId namespace_id;
    ObjectId object_id;

    PeerId origin;
    std::optional<PeerId> destination;

    ObjectType object_type;

    uint64_t created_at_ms;
    uint64_t ttl_ms;

    Priority priority;
    DeliveryClass delivery_class;

    uint32_t max_hops;
    uint32_t hop_count;

    uint64_t payload_size;
    Hash payload_hash;

    SecurityFlags security_flags;
};
```

The payload should be opaque to the network runtime.

Examples:

``` text
namespace: chat
type: message

namespace: chat
type: receipt

namespace: files
type: manifest

namespace: files
type: chunk

namespace: iot
type: command

namespace: sync
type: record
```

This gives the SDK a stable general-purpose foundation.

------------------------------------------------------------------------

# 5. Object Identity

Do not rely indefinitely on an arbitrary application `messageId`.

Use a structured, globally collision-resistant identifier.

Possible model:

``` text
ObjectID =
    NetworkID
    + OriginPeerID
    + random 128/192-bit nonce
```

or a content-addressed identifier where appropriate.

Requirements:

1.  globally unique;
2.  cheap to generate offline;
3.  impossible for another peer to predict usefully;
4.  stable across replication;
5.  independent of transport;
6.  safe as the dedup key;
7.  cryptographically bound to the signed object.

Do not make every object content-addressed automatically.
Mutable/control objects and privacy-sensitive objects may require opaque
IDs.

------------------------------------------------------------------------

# 6. Core SDK Modules

Recommended C++ structure:

``` text
network-runtime/
│
├── core/
│   ├── runtime/
│   ├── scheduler/
│   ├── lifecycle/
│   └── events/
│
├── identity/
│   ├── peer_id/
│   ├── key_store/
│   └── credentials/
│
├── crypto/
│   ├── handshake/
│   ├── signatures/
│   ├── encryption/
│   └── key_rotation/
│
├── transport/
│   ├── interface/
│   ├── quic/
│   ├── tcp/
│   ├── udp/
│   ├── lan/
│   ├── bluetooth/
│   └── relay/
│
├── connection/
│   ├── manager/
│   ├── session/
│   └── migration/
│
├── discovery/
│   ├── lan/
│   ├── known_peers/
│   ├── peer_exchange/
│   ├── bootstrap/
│   └── dht/
│
├── routing/
│   ├── peer_table/
│   ├── peer_selection/
│   ├── scoring/
│   └── path_policy/
│
├── storage/
│   ├── object_store/
│   ├── metadata/
│   ├── quota/
│   ├── eviction/
│   └── journal/
│
├── replication/
│   ├── inventory/
│   ├── anti_entropy/
│   ├── planner/
│   └── transfer/
│
├── delivery/
│   ├── store_forward/
│   ├── receipts/
│   ├── states/
│   └── reconciliation/
│
├── security/
│   ├── replay/
│   ├── authorization/
│   ├── abuse/
│   └── rate_limits/
│
├── resource/
│   ├── battery/
│   ├── bandwidth/
│   ├── storage/
│   ├── memory/
│   └── network_cost/
│
├── protocol/
│   ├── framing/
│   ├── schemas/
│   ├── negotiation/
│   └── capabilities/
│
├── telemetry/
│
├── simulator/
│
└── bindings/
    ├── c/
    ├── android-jni/
    └── future/
```

Keep module boundaries strict. Chat-specific state must not leak into
the core.

------------------------------------------------------------------------

# 7. Runtime Lifecycle on Android

A network OS for Android cannot depend on a permanent foreground service
for correctness.

Use three execution modes.

## 7.1 Active mode

App foreground or user actively communicating.

Characteristics:

-   live connections allowed;
-   aggressive direct delivery;
-   LAN discovery can be active;
-   reconciliation can happen immediately;
-   low-latency policy;
-   more CPU/network budget.

## 7.2 Opportunistic background mode

The app has legitimate background execution opportunity.

Characteristics:

-   process pending durable work;
-   synchronize inventories;
-   deliver high-priority pending objects;
-   expire old data;
-   compact databases;
-   avoid long-running discovery.

## 7.3 Dormant mode

Process dead/device asleep.

Correctness must survive this state.

Everything required to resume must be persisted:

-   local outbound objects;
-   carrier objects;
-   delivery states;
-   receipts;
-   peer knowledge;
-   retry metadata;
-   protocol migration state;
-   cryptographic identity.

When Android later allows execution, the engine reconstructs runtime
state from persistence.

This is a critical principle:

> **Process liveness is an optimization. Durable state is the source of
> truth.**

------------------------------------------------------------------------

# 8. Android Scheduling Strategy

Avoid independent timers in every subsystem.

Create one central scheduler:

``` cpp
class NetworkScheduler {
public:
    void schedule(Task task);
    void onConnectivityChanged(...);
    void onPeerAvailable(...);
    void onAppForeground(...);
    void onMaintenanceWindow(...);
};
```

Tasks should have metadata:

``` text
earliest run
deadline
priority
requires network
requires unmetered
requires charging
can batch
estimated bytes
estimated CPU
```

The Android binding can map suitable work to Android lifecycle
mechanisms such as WorkManager where appropriate.

The C++ core should not directly depend on Android APIs. Instead:

``` text
C++ Scheduler Policy
        ↓
Platform Scheduler Interface
        ↓
Android implementation
```

------------------------------------------------------------------------

# 9. Radio and Battery Strategy

The biggest battery mistake would be frequent periodic gossip.

Do not wake a phone every 20 minutes solely because a gossip timer
expired.

Prefer these triggers:

1.  app enters foreground;
2.  network becomes available;
3.  a peer connection already exists;
4.  LAN peer discovered while discovery is legitimately active;
5.  high-priority object arrives;
6.  scheduled maintenance opportunity;
7.  device charging;
8.  existing traffic already activated the radio.

The replication engine should ask:

``` text
Is replication useful now?
Is the radio already active?
Is the network metered?
Is battery low?
Is the device charging?
How many replicas already exist?
How urgent is this object?
```

Then adapt.

Example:

``` text
Critical message:
    replicate immediately to 3 suitable peers

Normal chat:
    replicate to 1-2 immediately
    increase later only if destination remains unavailable

Bulk metadata:
    defer until existing network activity

Large file:
    Wi-Fi / charging preferred
```

This is much more mobile-efficient than fixed epidemic flooding.

------------------------------------------------------------------------

# 10. Adaptive Replication

Replace fixed fan-out with a replication target.

Example policy:

``` cpp
struct ReplicationPolicy {
    uint8_t minimum_remote_copies;
    uint8_t desired_remote_copies;
    uint8_t maximum_remote_copies;

    Duration ttl;
    Priority priority;

    bool prefer_network_diversity;
    bool prefer_high_uptime_peers;
};
```

The runtime continuously knows approximate durability:

``` text
Local only                 D0
1 confirmed remote copy    D1
2 independent copies       D2
3 independent copies       D3
Destination accepted       D4
Destination signed ACK     D5
```

For a normal chat message:

``` text
target = D2
```

If one carrier disappears or expires:

``` text
current durability falls below target
             ↓
replication planner repairs redundancy
```

This is superior to continuously copying objects.

------------------------------------------------------------------------

# 11. Replica Leases

A major improvement for mobile storage is to make carrier storage a
**lease**.

Instead of assuming:

> Carrier C will hold this until TTL.

Use:

``` text
C accepts object X
lease expires in 6 hours
```

C returns a signed/validated storage acknowledgement containing:

``` text
object_id
accepted_until
storage_class
```

Before the lease becomes unsafe, another peer can take over.

Advantages:

-   carriers can manage storage honestly;
-   replication planner knows which copies are expected to survive;
-   phones do not make indefinite promises;
-   low-storage devices can offer short leases;
-   charging/always-on peers can offer longer leases.

This can become a major reliability primitive.

------------------------------------------------------------------------

# 12. Anti-Entropy Must Become Core

The current `poolDigest()` idea should become a core synchronization
protocol.

Do not gossip complete objects blindly.

Connection flow:

``` text
Peer A connects to Peer B
        ↓
capability negotiation
        ↓
compact inventory exchange
        ↓
determine missing/needed objects
        ↓
priority + policy selection
        ↓
transfer only useful objects
```

Possible inventory mechanisms:

-   exact ID lists for small sets;
-   Bloom filters;
-   Cuckoo filters;
-   range summaries;
-   Merkle trees for larger persistent datasets.

Start simple.

For a mobile-first v1:

-   exact compact IDs for small pools;
-   Bloom filter once pools become larger;
-   explicit `WANT` response;
-   batch object transfer.

Do not prematurely implement a complex distributed reconciliation
algorithm until simulation proves it is needed.

------------------------------------------------------------------------

# 13. Peer Selection

Random selection is acceptable only for the prototype.

Build a local peer score.

Possible inputs:

``` text
recent reachability
successful handoffs
observed uptime
latency
available storage
carrier willingness
network type
connection cost
failure rate
recent overload
protocol compatibility
```

Do not create a central reputation authority.

The score should initially be based on local observations.

Example:

``` text
Peer A:
    reliable Wi-Fi peer
    often available
    40 MB carrier capacity
    high score

Peer B:
    intermittent
    low capacity
    medium score

Peer C:
    repeated storage failures
    low score
```

Replica selection should also prefer **failure-domain diversity**.

Three copies on three peers behind the same temporarily disconnected LAN
are less valuable than three copies spread across independent
connectivity domains.

------------------------------------------------------------------------

# 14. Discovery Architecture

Discovery must be modular.

``` text
DiscoveryManager
├── LAN discovery
├── Known peer reconnect
├── Peer exchange
├── Optional bootstrap
├── Optional rendezvous
├── Optional DHT
├── BLE
└── Wi-Fi Direct
```

For mobile v1, do **not** begin with a permanently active global DHT.

Recommended order:

### Phase A

-   LAN discovery;
-   known-peer reconnect;
-   optional bootstrap/rendezvous;
-   peer exchange over established sessions.

### Phase B

-   NAT traversal improvements;
-   optional relay infrastructure.

### Phase C

-   evaluate DHT only after measuring whether it solves a real
    requirement efficiently.

A global DHT can create maintenance traffic, routing-table work,
wakeups, and complexity that may not be justified on phones.

------------------------------------------------------------------------

# 15. Optional Infrastructure Philosophy

Use:

> **No mandatory server**

rather than:

> **No server exists anywhere**

Allow optional:

-   bootstrap servers;
-   rendezvous nodes;
-   relay nodes;
-   NAT traversal services;
-   enterprise gateways;
-   high-availability community nodes.

The protocol must define graceful degradation.

If infrastructure exists:

``` text
better discovery + reachability
```

If it disappears:

``` text
known peers + LAN + peer exchange + existing connected components continue
```

This makes the system far more practical and still decentralized.

------------------------------------------------------------------------

# 16. Transport Layer

Create a strict transport abstraction.

``` cpp
class ITransport {
public:
    virtual TransportCapabilities capabilities() const = 0;
    virtual Result connect(const Endpoint&) = 0;
    virtual Result listen(...) = 0;
    virtual void close(...) = 0;
};
```

Do not expose socket details to the object/delivery layers.

Recommended long-term transports:

-   QUIC;
-   TCP;
-   UDP-based specialized transport if genuinely needed;
-   LAN;
-   BLE;
-   Wi-Fi Direct;
-   relay transport.

QUIC deserves serious evaluation for internet sessions because
connection migration and multiplexing are useful for mobile networks.

Do not rewrite a secure congestion-controlled transport unnecessarily if
a mature implementation satisfies the SDK's footprint requirements.

------------------------------------------------------------------------

# 17. Connection Manager

The connection manager should avoid keeping many idle sockets alive.

Maintain peer knowledge separately from active connections.

``` text
KnownPeer != ConnectedPeer
```

Use connection budgets.

Example:

``` text
Foreground:
    max active sessions: relatively generous

Background:
    max active sessions: small

Battery saver:
    critical sessions only
```

Prefer reusing an existing connection for multiple logical protocols.

Do not establish one socket per message/object.

------------------------------------------------------------------------

# 18. Multiplexing

A single secure peer session should carry multiple logical streams:

``` text
control
inventory
object transfer
receipt
application direct stream
```

This reduces handshakes, sockets, radio work, and battery cost.

Prioritize:

``` text
control > critical messages > receipts > normal messages > bulk
```

Prevent a large file transfer from blocking a small chat message.

------------------------------------------------------------------------

# 19. Security Architecture

Security must be layered.

## 19.1 Peer identity

Persistent cryptographic identity:

``` text
PeerID ↔ public key
```

Private keys should use platform-secure storage where practical.

The Android binding should integrate with Android Keystore for protected
key material where the chosen cryptographic design allows it.

## 19.2 Secure transport session

Authenticate peer sessions and encrypt traffic.

## 19.3 Origin signature

A carried object must remain verifiable after leaving the origin.

Signature should cover at minimum:

``` text
protocol version
network
namespace
object ID
origin
destination semantics
creation/lifetime
payload hash
relevant immutable policy fields
```

Do not sign mutable hop metadata as if it were origin-authored.

Separate immutable origin fields from mutable forwarding metadata.

## 19.4 End-to-end payload encryption

Storage/relay peers should not need application plaintext.

## 19.5 Replay protection

Persist a bounded replay/dedup index.

## 19.6 Key rotation

Design versioned identities/keys before deployment becomes large.

## 19.7 Authorization

A valid signature does not mean a peer is allowed to consume storage.

Authentication and authorization must be separate.

------------------------------------------------------------------------

# 20. Immutable vs Mutable Headers

Do not let carriers rewrite origin-authenticated fields.

Split the wire object:

``` text
SIGNED ORIGIN HEADER
    object ID
    origin
    destination
    created time
    TTL
    payload hash
    object type
    immutable policy

FORWARDING HEADER
    hop count
    previous peer
    local routing hints
    lease information

PAYLOAD
    encrypted application data

ORIGIN SIGNATURE
```

Each carrier can update forwarding metadata without invalidating the
origin signature.

------------------------------------------------------------------------

# 21. TTL and Clock Handling

The current fixed expiry concept is correct: gossip must never refresh
object life.

However, avoid blindly trusting arbitrary remote wall clocks.

Carry:

``` text
origin_created_at
ttl_duration
```

and define explicit clock-skew tolerance.

A peer should reject obviously unreasonable timestamps.

Use a monotonic clock for **local retry scheduling**, while preserving
wall-clock timestamps for durable protocol records.

Never persist a monotonic timestamp as a cross-reboot protocol time.

------------------------------------------------------------------------

# 22. Delivery State Machine

Use a richer state model.

Suggested conceptual states:

``` text
CREATED
QUEUED_LOCAL
INJECTING
REMOTE_ACCEPTED
REPLICATING
DURABILITY_REACHED
DELIVERY_ATTEMPTED
DELIVERED
CONFIRMED
EXPIRED
FAILED
CANCELLED
```

Not every application needs every state exposed.

Keep failure reason separate:

``` text
NO_ROUTE
NO_CARRIER
STORAGE_REJECTED
QUEUE_FULL
TTL_EXPIRED
AUTH_FAILED
POLICY_REJECTED
DESTINATION_REJECTED
RESOURCE_EXHAUSTED
PROTOCOL_ERROR
CANCELLED
```

Transitions must be idempotent.

Late confirmation should be able to upgrade an earlier uncertain/expired
application view when policy permits.

------------------------------------------------------------------------

# 23. Cryptographic Delivery Receipts

A receipt should be a first-class network object.

Conceptual receipt:

``` cpp
struct DeliveryReceipt {
    ObjectId object_id;
    Hash object_hash;

    PeerId origin;
    PeerId destination;

    uint64_t received_at_ms;
    ReceiptType type;

    Signature destination_signature;
};
```

Possible types:

``` text
RECEIVED
PROCESSED
READ
REJECTED
```

Do not confuse transport delivery with application processing.

A signed receipt gives the sender stronger evidence than an unverified
ACK.

Receipts themselves can use store-and-forward delivery.

------------------------------------------------------------------------

# 24. Storage Architecture

The object store is one of the most important components.

Separate logical classes:

``` text
LOCAL_OUTBOX
CARRIER_STORE
RECEIPT_STORE
DEDUP_INDEX
PEER_METADATA
SYSTEM_METADATA
```

The engine should expose transactions so that state cannot become
inconsistent after a crash.

Example atomic operation:

``` text
receive object
    ↓
verify
    ↓
persist object + dedup record
    ↓
commit
    ↓
send storage ACK
```

**Never acknowledge durable storage before the durable commit
succeeds.**

------------------------------------------------------------------------

# 25. Database Choice and Persistence Rules

The exact database can be selected after benchmarking, but requirements
are more important than brand:

-   crash-safe transactions;
-   small binary metadata;
-   indexed expiry;
-   indexed destination;
-   indexed namespace;
-   efficient batch deletion;
-   predictable disk usage;
-   corruption detection/recovery strategy.

For Android, minimize write amplification.

Batch metadata updates when correctness allows.

Avoid rewriting large blobs merely to update hop state.

Store payload/blob data separately from frequently updated metadata if
benchmarks show benefit.

------------------------------------------------------------------------

# 26. Storage Quotas

Use hierarchical quotas.

``` text
Global SDK quota
    ↓
Application/namespace quota
    ↓
Origin peer quota
    ↓
Object class quota
```

Example:

``` text
Network runtime total: 100 MB

System/control reserve: 5 MB
Chat carrier pool: 40 MB
Receipts: 5 MB
Other apps: allocated dynamically
```

Do not allow one hostile peer or one application to consume the entire
pool.

------------------------------------------------------------------------

# 27. Eviction Policy

Pure LRU is insufficient.

Eviction score can consider:

``` text
expired?
priority
remaining TTL
replica count
object size
storage lease
application class
delivery urgency
last access
origin quota pressure
```

Never evict critical system metadata just because it is old.

When a promised carrier copy is evicted early, record/report that fact
where the protocol can make useful corrective action.

------------------------------------------------------------------------

# 28. Backpressure

Every receiving path must be able to say "not now."

Protocol outcomes:

``` text
ACCEPTED
REJECTED_AUTH
REJECTED_POLICY
REJECTED_QUOTA
BUSY
RETRY_AFTER
UNSUPPORTED
```

Do not silently drop objects after pretending to accept them.

This is essential for honest reliability.

------------------------------------------------------------------------

# 29. Anti-Abuse

A decentralized carrier network is vulnerable to storage and bandwidth
abuse.

Minimum controls:

-   maximum object size;
-   maximum objects per origin;
-   maximum bytes per origin;
-   maximum write rate;
-   maximum control-message rate;
-   signature verification before expensive work;
-   bounded pending handshakes;
-   bounded decompression;
-   bounded parsing;
-   malformed frame rejection;
-   replay detection;
-   namespace authorization;
-   local peer blocking;
-   escalating rate limits.

Never allocate memory directly from an untrusted declared length without
checking configured bounds.

------------------------------------------------------------------------

# 30. Wire Protocol

Gson/JSON can remain at the application edge temporarily, but the
general-purpose C++ network protocol should use a compact versioned
binary representation.

Candidates include:

-   Protocol Buffers;
-   CBOR;
-   FlatBuffers;
-   carefully designed custom binary framing.

The most important properties are:

-   deterministic parsing rules;
-   explicit length limits;
-   backward compatibility;
-   unknown-field handling;
-   version negotiation;
-   fuzz-testability;
-   low allocation count;
-   low copy count.

Avoid designing an overly clever custom format before profiling.

------------------------------------------------------------------------

# 31. Framing

A frame should have a small fixed/compact prefix.

Conceptually:

``` text
MAGIC
PROTOCOL VERSION
FRAME TYPE
FLAGS
HEADER LENGTH
PAYLOAD LENGTH
CORRELATION / OBJECT ID
HEADER
PAYLOAD
AUTH DATA
```

All lengths must be validated before allocation.

Support streaming/chunking for large data rather than increasing one
frame to arbitrary size.

------------------------------------------------------------------------

# 32. Large Objects and Media

Do not replicate multi-megabyte media as one mailbox object.

Use:

``` text
Manifest
    ↓
content chunks
```

A manifest can contain:

``` text
content hash
total size
chunk size
chunk hashes
encryption metadata
source information
availability policy
```

Small chat envelopes can travel through the durable object network.

Large content can be requested opportunistically or replicated under a
different policy.

This avoids destroying mobile storage and bandwidth budgets.

------------------------------------------------------------------------

# 33. Zero-Copy / Low-Copy Data Path

Because the SDK is C++ and mobile-focused, aggressively avoid
unnecessary copies.

Target data path:

``` text
network buffer
    ↓
validated frame view
    ↓
crypto/decode
    ↓
persistent blob / application buffer
```

Use:

-   spans/views;
-   pooled buffers;
-   bounded arenas where useful;
-   move semantics;
-   streaming hashes;
-   streaming encryption;
-   scatter/gather I/O if supported.

Do not optimize blindly: measure allocations and copies first.

------------------------------------------------------------------------

# 34. Memory Budget

Create explicit memory modes.

Example conceptual targets:

``` text
Idle runtime:
    single-digit to low tens of MB

Background reconciliation:
    tightly bounded temporary buffers

Large transfer:
    streaming chunks, never whole-file RAM buffering
```

Maintain bounded caches.

Avoid keeping full carrier inventories in duplicated C++ and Java/Kotlin
representations.

JNI should exchange compact events/handles rather than copying entire
state repeatedly.

------------------------------------------------------------------------

# 35. JNI Architecture

Keep Android bindings thin.

``` text
Kotlin/Java API
      ↓
JNI facade
      ↓
C/C++ stable interface
      ↓
Network runtime
```

Do not make the C++ engine call arbitrary Java callbacks from many
native worker threads.

Prefer:

``` text
native event queue
      ↓
single JNI dispatch boundary
      ↓
Kotlin Flow/callback/event handling
```

This reduces complexity, thread bugs, and JNI overhead.

------------------------------------------------------------------------

# 36. Stable C ABI

Even if the main SDK is C++, expose a stable C-compatible ABI layer.

``` text
C++ engine
    ↓
C ABI
    ↓
Android JNI
    ↓
future Swift / Rust / Go / C# bindings
```

This protects the architecture from C++ ABI/compiler differences.

------------------------------------------------------------------------

# 37. Threading Model

Avoid "one thread per subsystem."

Recommended model:

-   one I/O event loop or a very small number;
-   bounded worker pool for CPU work;
-   dedicated persistence serialization only if benchmarks require it;
-   task scheduler;
-   no unbounded thread creation.

For an Android-first SDK, idle thread count matters.

Use asynchronous state machines rather than blocking threads waiting on
sockets/timers.

------------------------------------------------------------------------

# 38. Locking and Concurrency

Prefer ownership and message passing over shared mutable state.

Example:

``` text
ConnectionManager owns sessions
ObjectStore owns durable metadata
ReplicationManager submits requests
Scheduler coordinates tasks
```

Avoid global mutexes.

Define lock ordering if multiple locks cannot be avoided.

Use sanitizers in native test builds.

------------------------------------------------------------------------

# 39. Capability Negotiation

When peers connect, exchange a small capability document.

Possible fields:

``` text
protocol versions
supported transports
max frame size
max object size
carrier support
available carrier capacity class
chunking support
receipt support
compression support
security suites
namespace capabilities
```

Do not expose exact battery percentage or unnecessary device-identifying
information.

Privacy should influence capability design.

------------------------------------------------------------------------

# 40. Protocol Versioning

Separate:

``` text
SDK version
wire protocol version
application protocol version
object schema version
```

They are not the same.

Connection:

``` text
A supports wire v1-v3
B supports wire v2-v4
        ↓
negotiate v3
```

New optional features should be capability-negotiated.

Unknown optional fields should not crash old peers.

------------------------------------------------------------------------

# 41. Upgrade and Database Migration

Assume millions of devices may eventually run different versions.

Every persistent schema change must have:

-   schema version;
-   forward migration;
-   failure recovery;
-   rollback considerations;
-   test fixtures from old versions.

Never release a database migration that has only been tested on a fresh
install.

------------------------------------------------------------------------

# 42. Resource Manager

Create a first-class `ResourceManager`.

Inputs:

``` text
battery state
charging state
network metered/unmetered
connection type
data saver
storage pressure
thermal state if available
application foreground/background
OS scheduling opportunity
```

Outputs:

``` text
connection budget
replication budget
bandwidth budget
CPU budget
discovery intensity
storage acceptance
maintenance allowance
```

The C++ engine consumes abstract resource signals. The Android adapter
obtains them from Android.

------------------------------------------------------------------------

# 43. Resource Profiles

Useful profiles:

## ECO

-   minimal background work;
-   minimal replicas;
-   no opportunistic bulk;
-   discovery mostly on demand.

## BALANCED

-   normal default;
-   adaptive replication;
-   background reconciliation when convenient.

## RELIABLE

-   more redundancy;
-   faster repair;
-   higher carrier preference.

## CRITICAL

Per-object, not necessarily global:

-   immediate replication;
-   high priority;
-   stronger durability target.

Applications request service level; the OS/runtime still enforces hard
resource bounds.

------------------------------------------------------------------------

# 44. Reliability Model

Reliability should be defined mathematically and operationally.

Do not claim "effectively certain" without data.

Measure:

``` text
P(delivery before TTL)
P(receipt returned)
median delivery time
P95/P99 delivery time
replica survival
bytes per delivered object
wakeups per day
CPU ms per object
energy estimate per delivered object
```

Reliability depends on:

``` text
peer availability
network connectivity
replica count
peer diversity
TTL
destination online windows
routing efficiency
storage acceptance
```

------------------------------------------------------------------------

# 45. Simulation Before Large Deployment

Build a deterministic simulator early.

The simulator should run the same or closely related routing/replication
policy code used by the production runtime.

Simulate:

-   10 peers;
-   100;
-   1,000;
-   10,000;
-   eventually much larger logical populations.

Inject:

-   peer churn;
-   packet loss;
-   network partitions;
-   high latency;
-   clock skew;
-   storage exhaustion;
-   carrier refusal;
-   corrupted frames;
-   malicious peers;
-   duplicate delivery;
-   delayed receipts;
-   device reboot;
-   process kill;
-   changing IP;
-   intermittent destination availability.

Measure reliability and cost.

Do not tune replication constants by intuition alone.

------------------------------------------------------------------------

# 46. Chaos Testing on Real Android Devices

After simulation, create a device test harness.

Automate:

``` text
kill app process
force-stop where test conditions permit
toggle Wi-Fi
toggle mobile data
switch networks
reboot
fill storage
change time
disconnect peers
sleep device
wake device
upgrade SDK
downgrade test build
corrupt selected local state in test environment
```

The target is not merely "works in normal conditions."

The target is:

> **After interruption, the runtime always returns to a known,
> internally consistent state.**

------------------------------------------------------------------------

# 47. Fuzz Testing

Native networking code must be fuzzed.

Fuzz:

-   frame parser;
-   capability parser;
-   object header;
-   receipt parser;
-   inventory parser;
-   malformed length fields;
-   decompression inputs;
-   state transitions;
-   protocol negotiation.

Use ASan/UBSan in appropriate test configurations.

------------------------------------------------------------------------

# 48. Observability

Every important operation should have structured events.

Example object trace:

``` text
OBJECT_CREATED
LOCAL_COMMIT
REMOTE_STORAGE_REQUEST
REMOTE_STORAGE_ACCEPTED
REPLICA_TARGET_REACHED
DESTINATION_DISCOVERED
DELIVERY_STARTED
DESTINATION_COMMIT
RECEIPT_CREATED
RECEIPT_RECEIVED
CONFIRMED
```

Do not enable verbose logging by default on production phones.

Use:

-   ring buffers;
-   counters;
-   sampling;
-   opt-in diagnostics;
-   privacy-safe identifiers.

------------------------------------------------------------------------

# 49. Metrics

At minimum track:

``` text
delivery success
delivery latency
receipt latency
bytes sent/received
control overhead
replica count
storage usage
evictions
dedup hits
retransmissions
connection success
handshake latency
carrier acceptance rate
wakeups
background task duration
database size
memory high-water mark
```

These metrics should guide protocol tuning.

------------------------------------------------------------------------

# 50. Privacy

A decentralized network can leak metadata even when payloads are
encrypted.

Threat model should include:

-   who talks to whom;
-   destination identifiers visible to carriers;
-   timing;
-   object size;
-   peer presence;
-   repeated identifiers;
-   carrier inventory.

The first version may accept some metadata leakage, but document it
explicitly.

Do not claim "carriers cannot learn the destination" if the routing key
exposes the destination.

Long-term privacy improvements can include blinded routing identifiers,
rotating identifiers, or rendezvous techniques, but they should not be
added before the core protocol is reliable and measured.

------------------------------------------------------------------------

# 51. Sender/Carrier/Receiver Roles

Generalize current roles.

A device may simultaneously be:

``` text
Endpoint
Relay
Storage Peer
Gateway
Bootstrap helper
Observer
```

Roles are capabilities, not permanent node types.

A low-battery phone can temporarily advertise:

``` text
storage_carrier = false
relay = limited
```

while still receiving its own objects.

------------------------------------------------------------------------

# 52. Carrier Willingness

Storage participation must be explicit policy.

Possible user/application settings:

``` text
Do not carry third-party data
Carry on Wi-Fi only
Carry while charging
Maximum 50 MB
Maximum 100 MB
Contacts/groups only
Trusted network only
```

The core runtime translates these into carrier admission rules.

Do not make every phone an unlimited relay by default.

------------------------------------------------------------------------

# 53. Network Namespaces and Application Isolation

Every application/protocol gets a namespace.

``` text
system/*
chat/*
files/*
iot/*
sync/*
```

Each namespace has:

-   quota;
-   permissions;
-   priority ceiling;
-   object size limits;
-   carrier policy;
-   protocol version.

One application cannot consume all network resources.

------------------------------------------------------------------------

# 54. Application API

The public API should be simple.

Conceptually:

``` cpp
NetworkRuntime runtime(config);

runtime.start();

auto id = runtime.send(
    destination,
    namespace_id,
    payload,
    DeliveryPolicy{}
);

runtime.subscribe(namespace_id, handler);

runtime.cancel(id);

auto status = runtime.status(id);
```

Advanced APIs may expose direct streams and publish/subscribe later.

Applications should **not** implement:

-   gossip timers;
-   mailbox queries;
-   carrier replication;
-   dedup databases;
-   TTL cleanup;
-   peer scoring;
-   receipt routing.

Those belong in the runtime.

------------------------------------------------------------------------

# 55. Delivery Policy API

Conceptual:

``` cpp
struct DeliveryPolicy {
    Duration ttl;

    Priority priority;

    uint8_t minimum_remote_replicas;
    uint8_t desired_remote_replicas;

    bool require_destination_receipt;

    NetworkCostPolicy network_cost;
    CarrierPolicy carrier_policy;

    uint64_t max_payload_bytes;
};
```

The runtime may clamp unsafe values.

------------------------------------------------------------------------

# 56. Example Policies

## Normal chat

``` text
TTL: 48 hours
desired replicas: 2-3
receipt: required
metered network: allowed
priority: normal
```

## Urgent alert

``` text
TTL: 24 hours
desired replicas: higher
receipt: required
priority: critical
repair redundancy aggressively
```

## IoT command

``` text
TTL: 30 seconds
replicas: low
priority: critical
stale delivery forbidden
```

## File manifest

``` text
TTL: days
small object
replicated normally
```

## File chunks

``` text
large
separate bulk policy
prefer Wi-Fi/charging
```

------------------------------------------------------------------------

# 57. Direct Delivery vs Store-and-Forward

Use the cheapest path first.

``` text
Destination connected?
        │
       yes
        ↓
direct secure delivery
        │
        └── receipt

no
 ↓
store-and-forward
 ↓
replica target
```

Do not replicate unnecessarily when the destination has already durably
accepted the object.

------------------------------------------------------------------------

# 58. Pull + Push

Keep both mechanisms from the EDP proposal, but move them into the
runtime.

## Push

Carrier sees destination become reachable and attempts delivery.

## Pull

Returning endpoint reconciles with connected peers.

Pull is extremely important on mobile because it does not require every
carrier to continuously detect every destination.

A good mobile design should rely heavily on **reconciliation when a
useful connection already exists**.

------------------------------------------------------------------------

# 59. Reconciliation Session

When two peers connect:

``` text
1. authenticate
2. negotiate capabilities
3. exchange small state/inventory summaries
4. deliver objects directly addressed to each other
5. exchange receipts
6. repair high-priority replica deficits
7. optionally perform low-priority anti-entropy
8. close when no useful work remains
```

This can replace many independent background loops.

------------------------------------------------------------------------

# 60. Prioritized Reconciliation

Order work:

``` text
1. security/control
2. receipts
3. expired/cancellation information
4. objects for connected destination
5. critical replica repair
6. normal replica repair
7. low-priority/background data
```

This maximizes useful work per radio activation.

------------------------------------------------------------------------

# 61. Failure Semantics

Define exact meanings.

`NO_CARRIER` should mean something like:

> During the current injection attempt, no eligible peer accepted
> durable storage.

It must not necessarily mean:

> Delivery is permanently impossible.

Similarly:

`NO_ROUTE` may be transient.

`TTL_EXPIRED` is terminal for the original delivery policy.

Applications need to know which failures are retryable.

Add:

``` text
failure_class:
    TRANSIENT
    TERMINAL
    POLICY
    SECURITY
```

------------------------------------------------------------------------

# 62. Crash Consistency

Every protocol state transition should be designed against these failure
points:

``` text
before DB write
during DB write
after DB commit but before network ACK
after ACK send
before status callback
after callback but before app persists it
```

Because operations are idempotent, replay after restart should converge
to the correct state.

------------------------------------------------------------------------

# 63. Two-Phase Durable Handoff

The current R1 requirement should become a core primitive.

Correct flow:

``` text
Sender/Carrier
    ↓ OBJECT
Receiver/Carrier
    ↓ verify
    ↓ durable commit
    ↓ STORED_ACK
Sender/Carrier
    ↓ records remote durability
```

For final delivery:

``` text
Carrier
    ↓ OBJECT
Destination
    ↓ verify
    ↓ durable application/network commit
    ↓ RECEIVED_ACK
Carrier
    ↓ may release its copy according to policy
```

Never delete the last useful replica merely because bytes were written
to a socket.

------------------------------------------------------------------------

# 64. Replica Release

Do not immediately delete every carrier copy after one delivery unless
policy says so.

Possible rule:

``` text
Destination durable ACK obtained
        ↓
mark delivered
        ↓
retain minimal receipt/state briefly
        ↓
garbage collect replicas
```

If delivery confirmation itself can be lost, the destination must dedup
repeated delivery.

------------------------------------------------------------------------

# 65. Dedup

Dedup must persist for at least the meaningful object lifetime/receipt
window.

Use:

``` text
ObjectID → terminal/local state
```

Do not store full objects forever solely for dedup.

Compact terminal records can survive longer than payloads.

------------------------------------------------------------------------

# 66. Cancellation

General-purpose networking needs cancellation.

Origin may issue a signed cancellation object:

``` text
CANCEL object X
```

This should not promise impossible deletion from every offline peer, but
connected peers can stop forwarding and remove eligible copies.

Document cancellation semantics honestly.

------------------------------------------------------------------------

# 67. Priority Inversion Protection

A large low-priority transfer must not block:

-   receipt;
-   chat message;
-   control frame;
-   urgent command.

Use separate logical queues and fair scheduling.

------------------------------------------------------------------------

# 68. Congestion Control

Transport congestion control handles the link, but the runtime also
needs application-level admission.

If carrier storage or transfer queues grow:

``` text
reduce replica creation
defer low priority
reject bulk
preserve control/receipts
```

Reliability can decrease when over-replication causes congestion. More
copies are not always better.

------------------------------------------------------------------------

# 69. Compression

Compress only when useful.

Small encrypted payloads may gain little.

Do not compress untrusted encrypted data blindly.

For protocol metadata, compact binary encoding often gives more
predictable savings.

Measure CPU-versus-byte tradeoffs on mid-range Android hardware.

------------------------------------------------------------------------

# 70. Cryptographic Cost

Mobile crypto should be benchmarked.

Requirements:

-   modern algorithms;
-   hardware/platform acceleration where practical;
-   session reuse;
-   avoid repeated expensive handshakes;
-   batch signature verification only if security semantics remain
    correct;
-   cache verified immutable object metadata safely.

Do not weaken authentication to save battery.

Optimize architecture before cryptographic guarantees.

------------------------------------------------------------------------

# 71. Network OS Control Plane vs Data Plane

Separate them.

## Control plane

-   identity;
-   discovery;
-   capability negotiation;
-   peer health;
-   inventory;
-   routing hints;
-   storage offers;
-   receipts.

## Data plane

-   application objects;
-   chunks;
-   streams.

Control traffic must remain small and bounded.

------------------------------------------------------------------------

# 72. Do Not Build a Global DHT First

A DHT may eventually be useful, but it should not be the first answer to
global discovery.

For Android, persistent DHT maintenance can cost:

-   bandwidth;
-   wakeups;
-   connections;
-   CPU;
-   complexity.

First prove:

``` text
known peers
+ peer exchange
+ optional bootstrap
+ relays
+ opportunistic discovery
```

Then measure what remains unsolved.

------------------------------------------------------------------------

# 73. NAT and Internet Reachability

A truly useful mobile network needs a layered strategy:

``` text
direct path available?
    ↓ yes
use direct

no
 ↓
NAT traversal attempt

fails
 ↓
optional relay

relay unavailable
 ↓
store-and-forward through reachable peers
```

The architecture must allow multiple path types without application
changes.

------------------------------------------------------------------------

# 74. Multi-Path Future

Eventually, the connection manager may use:

-   Wi-Fi;
-   cellular;
-   LAN;
-   BLE;
-   Wi-Fi Direct;
-   relay.

Do not make routing assume a peer has exactly one address.

Use:

``` text
PeerID
    ↓
EndpointSet
```

Endpoints are temporary.

Identity is stable.

------------------------------------------------------------------------

# 75. Peer Table

Persist only useful peer knowledge.

Example:

``` text
PeerID
last successful contact
known endpoint hints
protocol capabilities cache
local reliability observations
backoff state
```

Do not persist huge historical telemetry forever.

Age stale information out.

------------------------------------------------------------------------

# 76. Retry Strategy

Never retry every object independently every 10 seconds.

Use:

-   exponential backoff;
-   jitter;
-   event-triggered retry;
-   batch retry;
-   destination availability event;
-   connectivity event.

Example:

``` text
failure
 ↓
backoff
 ↓
network changes
 ↓
retry early because new evidence exists
```

This saves substantial mobile resources.

------------------------------------------------------------------------

# 77. Wakeup Budget

Track wakeups as a first-class metric.

A feature that saves 5 KB but creates 100 extra wakeups may be a bad
mobile optimization.

Set test targets such as:

``` text
idle network:
    near-zero periodic wakeups

no pending work:
    no gossip timer churn

pending normal work:
    batch with existing opportunities

critical work:
    allowed to spend more energy
```

------------------------------------------------------------------------

# 78. Background Reliability Reality

Android may prevent the app from running for long periods.

Therefore the SDK cannot honestly guarantee that a sleeping phone will
continuously act as a carrier.

Reliability must come from:

-   multiple independent peers;
-   some peers naturally being active;
-   optional always-on nodes;
-   opportunistic handoffs;
-   long enough TTL where appropriate;
-   replica repair when execution becomes available.

Do not base guarantees on `START_STICKY` alone.

------------------------------------------------------------------------

# 79. Optional High-Availability Peers

The same protocol can support devices with different capabilities:

``` text
phone
tablet
desktop
home server
router
community relay
cloud VM
```

Phones remain first-class peers but are not required to behave like
datacenters.

High-availability nodes can advertise larger storage leases and capacity
without becoming mandatory central authorities.

This greatly improves reliability while preserving decentralization.

------------------------------------------------------------------------

# 80. Network Diversity

Replica placement should eventually consider correlated failure.

Avoid placing all replicas:

-   on the same LAN;
-   on peers with identical connectivity;
-   on peers that disappear together;
-   on the same physical device identity under multiple endpoints.

Start with simple diversity heuristics.

------------------------------------------------------------------------

# 81. Trust Levels

Do not make trust binary.

Possible local classes:

``` text
unknown
known
trusted
blocked
```

Storage policies can differ.

Example:

``` text
unknown peer:
    small quota

known peer:
    normal quota

trusted peer:
    larger quota
```

The exact social/trust model should remain application-configurable.

------------------------------------------------------------------------

# 82. Protocol Extensibility

Use typed frames.

Possible examples:

``` text
HELLO
CAPABILITIES
PING
OBJECT_OFFER
OBJECT_WANT
OBJECT_DATA
STORED_ACK
DELIVERY_ACK
INVENTORY
RECEIPT
BUSY
ERROR
CANCEL
```

Reserve ranges for future protocol modules.

Unknown optional frame types should be handled safely.

------------------------------------------------------------------------

# 83. API Compatibility

Once third-party applications use the SDK, API stability becomes
critical.

Use:

-   semantic versioning;
-   deprecation periods;
-   capability queries;
-   feature flags;
-   compatibility tests.

Avoid exposing internal structs directly as public ABI.

Use opaque handles/PIMPL/C ABI boundaries.

------------------------------------------------------------------------

# 84. Error Model

Use structured errors.

``` cpp
struct NetworkError {
    ErrorDomain domain;
    ErrorCode code;
    bool retryable;
    std::optional<Duration> retry_after;
};
```

Domains:

``` text
TRANSPORT
SECURITY
STORAGE
ROUTING
POLICY
RESOURCE
PROTOCOL
APPLICATION
```

Applications should not parse error strings.

------------------------------------------------------------------------

# 85. Configuration

Separate:

``` text
hard safety limits
runtime defaults
application policy
user preference
remote capability
```

A remote peer must never be able to raise local safety limits.

------------------------------------------------------------------------

# 86. Testing Matrix

Test at least:

``` text
Android API levels supported
32-bit/64-bit if applicable
low RAM
mid-range hardware
high-end hardware
Wi-Fi
mobile data
bad Wi-Fi
NAT variants
IPv4
IPv6
network switching
Doze
battery saver
low storage
process death
reboot
upgrade
clock changes
```

------------------------------------------------------------------------

# 87. Performance Benchmarks

Create repeatable native benchmarks for:

-   startup;
-   idle RAM;
-   idle CPU;
-   database open;
-   object insert;
-   batch insert;
-   dedup lookup;
-   inventory generation;
-   Bloom filter generation;
-   signature verify;
-   encryption;
-   frame parsing;
-   handshake;
-   reconnect;
-   1 KB transfer;
-   8 KB transfer;
-   1 MB streamed transfer.

Run on actual Android hardware, not only desktop.

------------------------------------------------------------------------

# 88. Suggested Initial Resource Targets

These are engineering targets to validate and revise, not guarantees.

For an idle Android runtime with no active work:

``` text
CPU: effectively 0% over long windows
network: no periodic internet chatter required
wakeups: near zero
active native threads: minimal
RAM: tightly bounded
disk: explicit configurable cap
```

For background work:

``` text
batch operations
bounded duration
bounded bytes
bounded memory
```

The most important rule is that **idle cost should approach zero**.

------------------------------------------------------------------------

# 89. Recommended Build Roadmap

## Phase 0 - Freeze and Measure Current SDK

Before major refactoring:

1.  document current modules;
2.  map threads;
3.  map socket ownership;
4.  map persistence;
5.  map mailbox implementation;
6.  map identity/crypto;
7.  map retry logic;
8.  map Android service lifecycle;
9.  benchmark idle CPU/RAM/network;
10. add structured tests.

Do not refactor what you cannot measure.

------------------------------------------------------------------------

## Phase 1 - Core Architecture Refactor

Create stable interfaces:

``` text
Runtime
Transport
Identity
ObjectStore
Scheduler
PlatformAdapter
```

Move ChatP2P-specific logic out of the core.

Deliverable:

> SDK starts, persists identity, opens transports, restores state, and
> shuts down cleanly.

------------------------------------------------------------------------

## Phase 2 - Secure Session Layer

Implement/harden:

-   authenticated peer identity;
-   secure transport;
-   protocol negotiation;
-   capability exchange;
-   reconnect;
-   bounded sessions.

Deliverable:

> Two Android devices can securely connect and maintain stable PeerID
> independent of address.

------------------------------------------------------------------------

## Phase 3 - Durable Network Object Store

Implement:

-   ObjectID;
-   generic object header;
-   payload storage;
-   transactions;
-   TTL;
-   quotas;
-   dedup;
-   crash recovery;
-   namespace isolation.

Deliverable:

> An object survives process death/reboot and restores correctly.

------------------------------------------------------------------------

## Phase 4 - Confirmed Remote Storage

Implement generalized R1/R2 primitives:

``` text
OBJECT_OFFER
OBJECT_DATA
durable commit
STORED_ACK
```

Add carrier leases.

Deliverable:

> Device A can obtain proof that Device C durably holds an object for B.

------------------------------------------------------------------------

## Phase 5 - Direct Destination Delivery

Implement:

-   direct delivery;
-   destination durable commit;
-   idempotent repeat delivery;
-   signed receipt;
-   reverse receipt object.

Deliverable:

> A can go offline after remote storage; B later receives; A later
> receives the receipt.

This is the first major EDP milestone.

------------------------------------------------------------------------

## Phase 6 - Anti-Entropy

Implement:

-   inventory;
-   WANT;
-   batch reconciliation;
-   replica knowledge;
-   compact summaries.

Deliverable:

> Peers synchronize missing carrier objects without blindly resending
> everything.

------------------------------------------------------------------------

## Phase 7 - Adaptive Replication

Implement:

-   durability target;
-   local peer score;
-   replica planner;
-   lease expiry;
-   replica repair;
-   diversity heuristics.

Deliverable:

> Replication changes based on actual durability instead of fixed
> gossip.

------------------------------------------------------------------------

## Phase 8 - Android Resource Manager

Integrate platform signals:

-   foreground/background;
-   charging;
-   battery;
-   metered network;
-   connectivity;
-   storage pressure.

Deliverable:

> The same protocol behaves aggressively when appropriate and nearly
> sleeps when idle.

------------------------------------------------------------------------

## Phase 9 - Discovery Expansion

Implement:

-   LAN;
-   known-peer reconnect;
-   peer exchange;
-   optional bootstrap;
-   optional rendezvous/relay.

Only add DHT after measurements justify it.

------------------------------------------------------------------------

## Phase 10 - Large Object Layer

Implement:

-   manifests;
-   chunks;
-   resumable transfer;
-   chunk hashes;
-   streaming;
-   bulk scheduling.

Do not mix bulk media behavior with tiny message behavior.

------------------------------------------------------------------------

## Phase 11 - Simulator and Chaos Lab

This should actually begin earlier, but by this stage it becomes a
release gate.

Validate:

-   delivery probability;
-   resource cost;
-   churn;
-   partitions;
-   malicious behavior;
-   crash recovery.

------------------------------------------------------------------------

## Phase 12 - Public General-Purpose SDK

Expose:

-   stable C ABI;
-   Android JNI/Kotlin API;
-   namespace registration;
-   delivery policies;
-   diagnostics;
-   compatibility contract.

ChatP2P becomes a reference application.

------------------------------------------------------------------------

# 90. What to Do With Current EDP R1-R11

Map them into generic runtime primitives.

  -----------------------------------------------------------------------
  Current request                     Generalized SDK direction
  ----------------------------------- -----------------------------------
  R1 Confirmed mailbox handoff        Durable object handoff protocol

  R2 Reverse-path mailbox             Destination-independent
                                      store-and-forward objects

  R3 Re-mailbox gossip                Replication manager

  R4 Durable outcomes                 Persistent event/state
                                      reconciliation

  R5 Per-message TTL                  Per-object lifetime policy

  R6 Storage quotas                   Resource and quota manager

  R7 Larger overlay payload           Framing + streaming/chunking

  R8 Serverless presence              Discovery/peer-event subsystem

  R9 Carrier health                   Local peer scoring/capabilities

  R10 Origin auth                     Immutable signed object envelope

  R11 Pool digest                     Core anti-entropy/inventory
                                      protocol
  -----------------------------------------------------------------------

This is the key transformation.

Do not implement R1-R11 as ChatP2P special cases.

------------------------------------------------------------------------

# 91. Things I Would Change in the Existing EDP Immediately

## Change 1

Replace:

``` text
message
```

internally with:

``` text
network object
```

## Change 2

Replace fixed gossip with adaptive replication and reconciliation.

## Change 3

Promote R11 anti-entropy from optional to core.

## Change 4

Separate immutable signed metadata from mutable forwarding metadata.

## Change 5

Replace `poolAck` with explicit durable-storage acknowledgement.

## Change 6

Create signed destination receipts.

## Change 7

Add storage leases.

## Change 8

Make failure reasons structured.

## Change 9

Make discovery modular.

## Change 10

Design Android lifecycle/resource management before adding more
background activity.

------------------------------------------------------------------------

# 92. Things Not to Build Yet

Avoid spending early engineering effort on:

-   blockchain;
-   global consensus;
-   global reputation;
-   token economics;
-   complex DHT;
-   onion routing;
-   full decentralized naming system;
-   arbitrary large media gossip;
-   globally synchronized network state;
-   exotic routing algorithms.

None of these are necessary to prove the core network runtime.

First make:

``` text
identity
secure connection
durable object
confirmed remote storage
offline delivery
receipt
anti-entropy
adaptive replication
crash recovery
resource efficiency
```

extremely reliable.

------------------------------------------------------------------------

# 93. Definition of "Rugged"

A rugged network layer should satisfy invariants such as:

1.  A malformed peer cannot cause unbounded allocation.
2.  A process crash cannot create an acknowledged-but-not-stored object.
3.  Replaying a frame cannot duplicate application delivery.
4.  Restarting during handoff converges to the correct state.
5.  Losing a carrier does not corrupt the sender's state.
6.  Expired objects do not live forever because of gossip.
7.  A low-storage device can reject storage honestly.
8.  A malicious peer cannot forge the origin.
9.  A carrier cannot modify encrypted application payload undetected.
10. One application cannot exhaust all SDK resources.
11. Idle runtime creates almost no work.
12. Network changes do not change peer identity.
13. Old and new protocol versions negotiate safely.
14. Every queue is bounded.
15. Every retry is bounded/backed off.
16. Every externally supplied length is validated.
17. Delivery status survives process death.
18. Late duplicate delivery is harmless.
19. The network can operate without mandatory infrastructure.
20. Optional infrastructure can improve reliability without becoming
    trusted central authority.

These invariants are more valuable than a large feature count.

------------------------------------------------------------------------

# 94. Suggested C++ Public Model

Illustrative only:

``` cpp
class NetworkRuntime {
public:
    Result start();
    Result stop();

    SendResult send(
        const Destination& destination,
        NamespaceId ns,
        ByteView payload,
        const DeliveryPolicy& policy);

    Result cancel(const ObjectId& id);

    DeliveryStatus status(const ObjectId& id);

    Subscription subscribe(
        NamespaceId ns,
        ObjectHandler handler);
};
```

Internal API:

``` cpp
class ObjectStore;
class ReplicationManager;
class ConnectionManager;
class DiscoveryManager;
class ResourceManager;
class PeerSelector;
class ProtocolEngine;
class ReceiptManager;
class NetworkScheduler;
```

Keep internal modules replaceable.

------------------------------------------------------------------------

# 95. Suggested Android API Shape

The Android-facing layer should feel Android-native while keeping the
logic native.

Conceptually:

``` kotlin
NetworkSdk.start(context, config)

val id = NetworkSdk.send(
    destination = peerId,
    namespace = "chat",
    payload = bytes,
    policy = DeliveryPolicy.reliable()
)

NetworkSdk.deliveryEvents.collect { event ->
    // UI/database integration
}
```

The Kotlin layer should not implement routing.

It should mainly provide:

-   lifecycle bridge;
-   platform resource signals;
-   secure key integration;
-   application callbacks;
-   Android scheduling bridge;
-   permissions/connectivity integration.

------------------------------------------------------------------------

# 96. Mobile-First Decision Hierarchy

Whenever two designs are both correct, choose in this order:

``` text
1. correctness
2. security
3. crash consistency
4. bounded resource use
5. battery/wakeup efficiency
6. network efficiency
7. latency
8. implementation convenience
```

For critical traffic, policy may temporarily trade more battery for
reliability/latency.

------------------------------------------------------------------------

# 97. Central Architectural Insight

Do not try to make a phone behave like a permanently running router.

Instead make the network tolerate the fact that phones are unreliable
infrastructure.

That means:

``` text
phone sleeps
    → okay

process dies
    → okay

IP changes
    → okay

carrier disappears
    → repair replicas

destination offline
    → durable storage

sender offline
    → network continues

receipt delayed
    → durable reverse delivery

network partition
    → components continue independently

partition heals
    → anti-entropy reconciles
```

This is how the system becomes rugged.

------------------------------------------------------------------------

# 98. Recommended First Concrete Engineering Sprint

Before writing new protocol features, inspect the current SDK and
produce an architecture map containing:

``` text
current C++ classes
thread ownership
socket ownership
event loop
transport protocol
frame format
encryption/authentication
PeerID generation
peer table
discovery
mailbox storage
durable outbox
retry scheduler
dedup
callbacks
Android foreground service
JNI boundary
configuration
database/files
```

Then classify every current component as:

``` text
KEEP
HARDEN
REFACTOR
REPLACE
MOVE TO APP
MOVE TO CORE
```

After that, implement the generic `NetworkObject + ObjectStore`
foundation before expanding gossip.

------------------------------------------------------------------------

# 99. Suggested First Technical Milestone

The first milestone for the new architecture should be deliberately
small:

### Scenario

``` text
A, B, C are Android devices.

B is offline.

A creates object X addressed to B.

A durably stores X locally.

A securely connects to C.

C verifies X.

C durably commits X.

C sends STORED_ACK.

A records remote durability.

A is killed/offline.

Later B connects to C.

C offers X.

B verifies and durably commits X.

B returns signed delivery receipt.

C safely marks/releases X.

B injects/forwards receipt for A.

Later A starts.

A receives receipt.

A marks X CONFIRMED.
```

Now repeat the scenario while killing the process at **every single
arrow**.

If the protocol always recovers correctly, you have the beginning of a
rugged network layer.

Only after this milestone should multi-carrier replication become the
next major focus.

------------------------------------------------------------------------

# 100. Long-Term Vision

The final platform can evolve into:

``` text
                 Mobile Network OS
                        │
       ┌────────────────┼─────────────────┐
       │                │                 │
   Messaging       Data Sync       Distributed Files
       │                │                 │
       ├────────────────┼─────────────────┤
       │                │                 │
      IoT            Backup          App Services
       │                │                 │
       └────────────────┼─────────────────┘
                        │
                 Network Objects
                        │
        Secure Store / Route / Replicate
                        │
       Adaptive Mobile Resource Runtime
                        │
     QUIC / TCP / LAN / BLE / Relay / Future
```

The SDK should provide the network properties; applications should
provide meaning.

------------------------------------------------------------------------

# 101. Final Recommendation

The project should move forward, but the next step should **not** be to
bolt more mailbox behavior directly onto ChatP2P.

Use ChatP2P EDP as the first demanding application and test case.

Refactor the C++ SDK into a general-purpose mobile networking runtime
around these core primitives:

1.  stable cryptographic peer identity;
2.  transport abstraction;
3.  secure multiplexed peer sessions;
4.  generic durable network objects;
5.  transactional object store;
6.  confirmed durable handoff;
7.  signed delivery receipts;
8.  anti-entropy reconciliation;
9.  adaptive replication;
10. peer selection;
11. modular discovery;
12. explicit quotas/backpressure;
13. resource-aware scheduler;
14. Android lifecycle bridge;
15. crash recovery;
16. protocol/version negotiation;
17. simulator/chaos testing;
18. structured observability.

For Android, **do not equate reliability with continuously running
background code**. Make persistence and idempotent reconciliation the
foundation. Use active connectivity opportunities efficiently, batch
work, repair redundancy intelligently, and allow stronger peers to
contribute more without making them mandatory.

If this principle is maintained, the SDK can remain extremely light on a
phone while still behaving like a reliable distributed network layer.

------------------------------------------------------------------------

## Appendix A - Recommended Priority Order

``` text
P0  Crash consistency
P0  Identity/security
P0  Bounded resources
P0  Generic object store
P0  Confirmed handoff

P1  Receipts
P1  Anti-entropy
P1  Adaptive replication
P1  Android resource manager
P1  Peer scoring

P2  Expanded discovery
P2  Optional relays/bootstrap
P2  Chunked large objects
P2  Multi-transport

P3  DHT if justified
P3  Advanced privacy routing
P3  Sophisticated reputation
P3  Distributed service extensions
```

------------------------------------------------------------------------

## Appendix B - Mobile Reliability Rule

A useful rule for every subsystem:

> **If correctness requires the Android process to remain alive,
> redesign the subsystem.**

The process may help the network while it is alive, but durable protocol
state must make death and restart ordinary events.

------------------------------------------------------------------------

## Appendix C - Success Criteria for v1 Network Runtime

A v1 should be considered successful when:

-   three Android phones can complete sender-offline store-and-forward
    delivery;
-   every protocol stage survives process death;
-   duplicate frames do not duplicate application delivery;
-   sender receives a verifiable final receipt;
-   TTL remains fixed across forwarding;
-   storage is strictly bounded;
-   carrier refusal is explicit;
-   no mandatory central server is required for an already
    connected/discoverable component;
-   idle CPU/network activity is close to zero;
-   normal operation does not require frequent polling;
-   protocol state can be inspected and debugged;
-   multiple SDK/application versions can negotiate safely;
-   simulated churn demonstrates measured reliability rather than
    assumed reliability.

That is the foundation on which the broader network-layer OS should be
built.
