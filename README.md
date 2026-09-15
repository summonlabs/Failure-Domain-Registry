# Failure Domain Registry

Failure Domain Registry is the authoritative correlated-failure classification
runtime of the Distributed Fabric Infrastructure ("Fabric OS") stack. It
answers one question:

> Which infrastructure entities share a common failure domain, how are those
> domains related, which memberships and correlation classes are authoritative,
> which generation of that classification is current, and when must a
> failure-domain claim be rejected, superseded, fenced, retired, or
> revalidated?

It is a vendor-neutral C++20 library with a small set of executables. It has no
third-party dependencies.

Version 1.0.0. Persisted state format version 1. Wire protocol version 1.

---

## 1. Systems boundary

Failure Domain Registry establishes **which entities share a common failure
factor** and **whether that classification is current and authoritative**. It
never establishes what an entity is, where it sits, whether it is up, or what
should be done about the risk.

### It owns

* Failure-domain identity, class, generation, lifecycle and provenance.
* Domain-to-domain relations that express failure correlation.
* Failure-domain membership as a first-class record with its own identity,
  generation, evidence set and lifecycle.
* Shared-risk and correlated-failure grouping.
* Direct, derived, inherited and asserted membership, and the derivation rules
  that produce the derived ones.
* Entity-generation and domain-generation binding of membership.
* Deterministic membership validation, determinism of overlap and independence
  answers, stale-generation fencing, supersession, retirement and
  revalidation.
* Classification coverage, and the UNKNOWN that follows from incomplete
  coverage.
* Immutable snapshots, stable diffs, a canonical state digest and deterministic
  explanations.
* Versioned, integrity-checked persistence and conservative recovery.
* Distributed publication authority: which publisher incarnation, under which
  coordinator epoch, may change which domain classes and scopes.

### It explicitly does not own

| Adjacent runtime | What it owns, and this repository does not |
| --- | --- |
| Fabric Registry | Canonical infrastructure identity and entity generations |
| Fabric Topology | Structural connectivity, containment and topology generations |
| Link State Fabric | Live link up/down/degraded state |
| Port Fabric | Port configuration and operational semantics |
| Fabric Capability Registry | What a device is capable of |
| Path Diversity Fabric / Path Authority | Path computation and path authority |
| Route Fabric | Route computation and programming |
| Failover and recovery runtimes | Failover execution, recovery planning |
| Schedulers and placement | Admission, placement, scheduling |
| Power and cooling control | Any actuation |

The registry classifies correlated risk. It does not decide what any downstream
system must do about that risk, and it does not model failure probability.

---

## 2. Why correlated failure is not topology, health or ownership

Two links can be topologically separate and still share a conduit or an optical
amplifier. Two switches can sit on different topology branches and share a rack
power feed. Two ports on one switch can share a chassis domain but sit in
different ASIC domains. Two devices in one rack can be on different power
domains. Two sites can share an upstream carrier.

A failure domain can exist while nothing is failed. Membership is not a health
statement, not a prediction and not a redundancy policy. Persisted membership
does not become valid again merely because it was written to disk, and it does
not transfer to a replacement entity by itself.

IDENTITY, TOPOLOGY, FAILURE-DOMAIN MEMBERSHIP, LIVE FAILURE STATE and FAILOVER
POLICY are therefore five separate concerns with five separate owners, and this
runtime owns exactly one of them.

---

## 3. Domain classes

A classification is either one of 29 canonical classes or it lives in an
explicit vendor or administrative extension namespace. There is no free-form
`type` string.

```
device           chassis          line-card        asic
port-group       link             cable            conduit
transceiver-group optical-component rack            row
pod              fabric           site             building
power-feed       power-bus        pdu              ups
generator        cooling-zone     network-provider wan-circuit
control-plane    firmware-group   software-control-group
administrative   custom
```

Extensions are spelled `vendor:<namespace>/<name>` or
`admin:<namespace>/<name>`, where both components are bounded and restricted
to `[a-z0-9._-]`. An extension can never be used to smuggle an arbitrary string
into the classification space, and an extension is never treated as exclusive,
because this runtime cannot prove the physical semantics of a vendor-defined
class.

Exclusivity is a typed property of a class, never a global rule. It holds for
`chassis`, `line-card`, `asic`, `port-group`, `rack`, `row`, `pod`, `building`,
`site` and `fabric`: an entity occupies one of each. It does not hold for
power, cooling, conduit, cable, optical, carrier, control-plane, firmware or
software classes, where multiple simultaneous membership is the normal and
correct case. `fdr-cli classes` prints the table the code enforces.

---

## 4. Domain identity and the domain record

`FailureDomainId` is a 128-bit value rendered as 32 lowercase hex characters.
It is derived deterministically from `(administrative scope, domain class,
identity key)` by truncating a SHA-256 over a domain-separated canonical byte
string. Two publishers naming the same factor in the same scope and class
therefore address the same domain rather than creating duplicates, and a
replay cannot invent a second identity.

A domain record carries: identity, class, generation, lifecycle, an optional
canonical name (never an identity), administrative scope, provenance, the
generation it was created at, supersession lineage (`supersedes`,
`superseded_by`, `merged_into`), bounded metadata and bounded history.

It carries no live failure state, no health, no probability and no policy.

### Hierarchy and orthogonal overlap

Domains form a graph, not a tree. One switch may belong simultaneously to a
rack, a PDU, a cooling zone, a firmware group and a control-plane group, and
those domains are orthogonal.

Domain-to-domain relations are typed and closed: `CONTAINED_BY`, `DEPENDS_ON`,
`SHARES_RISK_WITH`, `POWERED_BY`, `COOLED_BY`, `CONTROLLED_BY`, `BACKED_BY`,
`CORRELATED_WITH`. Acyclicity is a property of the relation type, not of the
graph: containment, dependency, power, cooling, control and backing relations
must stay acyclic and are rejected with `CYCLE_REJECTED` when they would close
a cycle, while `SHARES_RISK_WITH` and `CORRELATED_WITH` are symmetric and may
legitimately form arbitrary graphs. `CONTAINED_BY` additionally requires both
endpoints to be containment classes; anything else is `INVALID_HIERARCHY`.

---

## 5. Membership

Membership is a first-class record, never a vector buried inside a domain.

A membership binds: its own identity, the domain and the exact domain
generation, the member entity reference including the exact entity generation,
its own generation, its kind, its role, its dependency semantics, an evidence
set, its derivation metadata, its lifecycle, its supersession lineage, bounded
metadata and bounded history.

`MembershipId` is derived from `(kind, domain id, entity class, entity bytes,
entity generation)`. The entity generation is part of the identity, so a
membership established against switch generation 3 can never silently become a
membership of switch generation 4: it is a different record, and the older one
is demoted when the replacement is reported.

### Direct versus derived membership

`MembershipKind` distinguishes `DIRECT`, `DERIVED`, `INHERITED` and `ASSERTED`.
Nothing is ever derived silently. Derived membership is produced only by a
published, versioned, deterministic rule, and each derived record preserves the
rule identity, the derivation generation, the exact source membership ids, the
exact source generations, and a canonical context string. When a source
generation moves on, the derived membership is recomputed or withdrawn - it is
never left quietly standing.

Two operators exist, and only two:

* `members-share-containing-class` - every current member of a domain of the
  source class receives derived membership in every target-class domain that at
  least one of those members belongs to.
* `same-domain-member-relationship` - a member inherits the target-class
  domains of a co-member of a named entity class within the same source-class
  domain.

There is no scripting hook and no pluggable callback.

### Dependency semantics

`DependencySemantics` records `ANY_DEPENDENCY_FAILURE_AFFECTS_MEMBER`,
`ALL_DEPENDENCIES_REQUIRED` or `REDUNDANT_SOURCE`. A dual-PSU server attached
to two PDUs is represented as two memberships with explicit roles; the registry
never collapses that into "failure of either PDU kills the server" and never
fabricates a resilience conclusion.

---

## 6. Generations, fencing and idempotency

Explicit generations exist for the registry, each domain, each membership, the
evidence, each derivation, each publisher grant, each snapshot, each entity and
the topology facts this runtime reads.

* An exact replay of an already committed mutation returns `IDEMPOTENT` and
  advances nothing.
* The same mutation attempt id replayed with different content returns
  `CONFLICTING_REPLAY`.
* A request whose expected generation is no longer current returns
  `STALE_GENERATION`, `STALE_DOMAIN`, `STALE_MEMBERSHIP` or `STALE_ENTITY`
  before anything is written.

Authority binds a `PublisherId`, a `WorkerBootId`, a `CoordinatorEpoch`, an
`AuthorityScope` (allowed domain classes, an optional administrative scope and
a maximum evidence class) and a mutation attempt. Connecting is not authority.

* A restarted publisher receives a fresh worker boot id; the previous
  incarnation is permanently fenced.
* Fenced traffic cannot create domains, attach or withdraw membership,
  supersede current membership, retire domains, restore stale classification or
  clear `REVALIDATION_REQUIRED`.
* A restarted coordinator advances its epoch, fences every live incarnation and
  rejects old-epoch traffic.
* Durability does not imply current process authority: after a restart, every
  process-bound evidence entry is fenced and demoted, while durable
  administrative classification is preserved because its evidence never
  depended on a live process.

---

## 7. Overlap, independence and coverage

`overlap` answers which current failure domains two or more entities share,
including which of them are the most specific (no other shared domain is one of
their descendants), and returns every relevant class rather than forcing a
single answer.

`independence` distinguishes `PROVEN_INDEPENDENT`, `SHARED_DOMAIN`, `UNKNOWN`,
`REVALIDATION_REQUIRED`, `CONFLICTED` and `NO_KNOWLEDGE`. Absence of a
membership record is never treated as proof of independence: a negative answer
requires `COMPLETE` coverage for every addressed class in every effective
scope. `PARTIAL` and undeclared coverage both produce `UNKNOWN`.

Coverage is declared per `(administrative scope, domain class)` with an
explicit evidence class and truth class. The weakest declaration for a scope
and class wins, so a later strong claim cannot silently upgrade a weaker one.

`blast_radius` returns current membership plus child-domain structure. It states
membership; it never simulates failure and never claims affectedness.

`correlate_member_sets` accepts two caller-supplied member sets and reports the
shared domains, the shared classes, the classes with unknown coverage and
whether independence is proven. It never computes a path and never enumerates
links: the caller supplies the sets, and Path Diversity Fabric or the path
planner owns the path.

---

## 8. Snapshots, digests and diffs

A `Snapshot` binds an id, a sequence, the registry generation, the coordinator
epoch, the exact domain and membership generations with their lifecycle,
provenance and derivation identity, and a SHA-256 digest. It is an immutable
value: a later mutation cannot change what a snapshot says. `snapshot_is_current`
compares generations, and old snapshots remain inspectable without being
current.

The canonical state digest is a SHA-256 over a canonical byte string in which
every record is written in identity order, every container in a fixed order and
every variable-length field is length framed. Process-local bookkeeping (the
registry generation at which a record happened to be created) is deliberately
excluded.

**Known limitation.** The digest is *not* fully arrival-order independent, and
the test suite pins this: membership and provenance canonical forms carry an
evidence generation drawn from one per-registry counter, so two registries that
reached the same classification by different publication orders can differ.
`DomainRelation::canonical_form()` additionally includes `created_at` and
`created_epoch`, which the domain and membership forms exclude. Within one
registry the digest is stable and deterministic.

`diff` reports a stable, totally ordered change list over 12 change kinds.

---

## 9. Persistence and recovery

The persisted container is a single file:

```
magic        8 bytes   "FDRSTATE"
version      u32       format version, currently 1
flags        u32       reserved, must be zero
payload u64  length in bytes
payload sha  32 bytes  SHA-256 over the payload
header sha   32 bytes  SHA-256 over the preceding 56 bytes
payload      N bytes   deterministic record encoding
trailer      6 bytes   "FDREND"
```

The file size must equal `88 + N + 6` exactly and the trailer must be present
at that offset, so a truncation at any byte position is rejected before a
single record is decoded. Decoding is bounds-checked throughout, uses checked
arithmetic for every count, and rejects duplicate domains, duplicate
memberships, duplicate relations, malformed identifiers, invalid classes,
invalid lifecycles, impossible generations, dangling relations and trailing
bytes. Replacement is atomic: the image is written to a sibling temporary file,
flushed, verified by reading it back, and renamed over the destination.

Recovery is conservative. Durable classification survives; live sessions are
never restored; every process-bound evidence entry is fenced with
`coordinator-restart` and demoted to `REVALIDATION_REQUIRED`; the coordinator
epoch advances; old-epoch traffic is rejected; derived membership is
recomputed from current sources.

---

## 10. Distributed publication

The control path is framed TCP on loopback. A frame is a 28-byte header
(`magic`, protocol version, message type, reserved flags, payload length, per-
connection sequence, integrity) followed by a field-by-field encoded payload.
No raw C++ object layout crosses the wire, every frame is bounded, the payload
integrity is checked, and decoding ends with a trailing-byte check.

`fdr-coordinator` owns the registry, the durable image and the listening
socket. `fdr-publisher` is a separate operating-system process with its own
publisher identity, its own worker boot id and its own connection. Session loss
is detected through the real socket, and a lost session fences exactly the
incarnation that owned it; unrelated publishers and their classification are
untouched.

Teardown is explicit. On Windows a blocking receive is not woken by `shutdown`
alone in every stack state, so every orderly teardown is: `shutdown(both)`, the
reader observes the stop flag, and the handle is closed by the thread that owns
it - never while another thread is inside `recv`. `Coordinator::stop` joins the
session threads and must not be called from one.

---

## 11. REAL, SYNTHETIC and UNSUPPORTED

Evidence is labelled truthfully and never upgraded.

**REAL.** `discover_host_evidence()` reads the local operating system's Plug
and Play device tree on Windows: device instance paths, parent device instance
paths and device instance containers, which group the functions of one physical
device. That is genuine host evidence and is labelled `REAL`.

It is also narrow. A container proves that a set of device nodes are functions
of one device. It does not prove rack, row, pod, building, PDU, power feed,
power bus, UPS, generator, cooling zone, conduit, cable, optical component,
transceiver group, WAN circuit, network provider, site, fabric, line card, ASIC
or port-group classification, and this runtime never claims otherwise.
`fdr-cli host-evidence` prints that list of UNSUPPORTED classifications next to
the evidence it did collect.

**SYNTHETIC.** `build_synthetic_dataset()` deterministically generates a
multi-site installation with device, ASIC, chassis, rack, PDU, dual-power, pod,
site, conduit, fibre-span, optical, carrier, firmware-group, control-plane and
cooling-zone domains, orthogonal overlap, replacement and deliberately
incomplete coverage. Every record it produces carries
`ProvenanceSource::SyntheticTestSource`, `EvidenceClass::Synthetic` and
`TruthClass::Synthetic`, and nothing in that path may be presented as physical
discovery.

**UNSUPPORTED.** Anything that cannot be observed here is reported as
UNSUPPORTED rather than approximated.

---

## 12. Build

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Options: `FDR_BUILD_TESTS`, `FDR_BUILD_TOOLS`, `FDR_BUILD_EXAMPLES`,
`FDR_BUILD_BENCHMARKS`, `FDR_WARNINGS_AS_ERRORS` (default ON),
`FDR_SANITIZERS` (default OFF), `FDR_ANALYZE` (MSVC static analyzer, default
OFF), `BUILD_SHARED_LIBS` (default OFF).

### Sanitizers and static analysis

`FDR_SANITIZERS=ON` requests AddressSanitizer. On MSVC it is a hard
configuration error when the optional C++ AddressSanitizer component is not
installed, and on GCC and Clang it is a hard configuration error when the
sanitizer runtime is unavailable: the build never silently proceeds without the
instrumentation that was asked for. On this host the MSVC AddressSanitizer
component is not installed, so sanitizer instrumentation is UNSUPPORTED here and
the strongest available substitutes are used instead: the MSVC static analyzer
(`FDR_ANALYZE=ON`, `/analyze`) and the Debug configuration's `/RTC1` runtime
checks with `_ITERATOR_DEBUG_LEVEL=2`.

On MSVC the project builds with `/W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc`
and `/WX`; Release adds `/O2 /Gy /Gw`, Debug adds `/RTC1` and
`_ITERATOR_DEBUG_LEVEL=2`. No warning is suppressed project-wide.

## 13. Test

```
ctest --test-dir build --output-on-failure
```

Each translation unit in `tests/` becomes one test executable; `tests/support`
is the shared harness and `tests/package_consumer` is a standalone downstream
project configured separately against an installed tree. No test uses a timeout
and no test hides a hang behind a watchdog.

## 14. Install and consume

```
cmake --install build --prefix /some/prefix
```

```cmake
find_package(FailureDomainRegistry CONFIG REQUIRED)
target_link_libraries(app PRIVATE SummonSoftwareLabs::FailureDomainRegistry)
```

```cpp
#include <failure_domain_registry/failure_domain_registry.hpp>
```

The installed package exports exactly the headers, the library and the
`SummonSoftwareLabs::FailureDomainRegistry` imported target. Nothing this
project uses for itself leaks into it.

## 15. Tools

```
fdr-cli version | classes | lifecycle | limits | host-evidence | synthetic [SEED]
fdr-cli inspect PATH      # verify and describe a persisted image
fdr-cli dump PATH         # load an image and print its classification
fdr-coordinator [--bind A] [--port P] [--state PATH] [--grant SPEC] [--no-persist]
fdr-publisher --endpoint HOST:PORT --publisher HEX --boot HEX [--label T] [--evidence C]
```

`fdr-publisher` reads one command per line on standard input and writes exactly
one deterministic result line per command (`OK <CODE> ...` or `ERR <CODE> ...`),
so a script or a test can drive a real publisher process over the real control
path.

## 16. Ownership, lifetime and thread safety

`Registry` is neither copyable nor movable and is the sole owner of its mutable
state. Queries return values: no query hands out a reference into registry
state and no query exposes a mutable container. `Snapshot`, `FailureDomain`,
`Membership`, `Outcome` and `Explanation` are independent values whose lifetime
is not tied to the registry.

Every public `Registry` method is safe to call from any thread. Queries take a
shared lock and mutations take the exclusive lock; both hold it only for the
duration of the state change, never across persistence I/O, never across a
caller-supplied callback, and never across a nested registry call that would
reacquire the lock. `Coordinator` owns its accept thread and its session
threads; `PublisherClient` serialises its own request/response exchanges.

The locking contract is stated in `src/registry_internal.hpp` and is honoured
by every translation unit in `src/`.

---

## 17. Limitations

* The registry classifies correlated risk. It does not model probability, and
  it deliberately exposes no risk score.
* Conflict resolution is a total order over evidence classes. Two equally
  strong facts from different sources are never adjudicated automatically: the
  record is marked `CONFLICTED` and an operator must resolve it.
* Domain merge exists and is transactional; domain split does not exist in this
  version. A split is expressed as two new domains plus explicit member
  redistribution followed by a supersession of the old domain.
* The persisted state is a single file with a single writer. There is no
  replication and no consensus.
* Key material is not used to authenticate peers. Authority is bound to a
  publisher incarnation and a coordinator epoch on a trusted loopback control
  path; running the coordinator on an untrusted network requires an
  authenticating transport.
* Snapshot entries are identity-level records (identity, generation, lifecycle,
  provenance class, derivation identity) rather than full copies of every
  record body, so a snapshot stays cheap for very large registries; a consumer
  that needs a full body re-queries the record by identity.
* `max_hierarchy_depth`, `max_record_bytes`, `max_history_query` and
  `max_snapshots_retained` are validated but not yet consulted by the paths they
  name, and `max_memberships` is not enforced on the bulk publication path.
  `ancestors()` and `descendants()` truncate silently at
  `max_ancestor_walk` rather than reporting truncation.
* `DomainClassRef::parse` accepts dot-only extension segments, so `vendor:../..`
  is accepted; extension segments are bounded and character-restricted but not
  yet rejected when they consist solely of dots.
* `Registry::load` accepts an image whose membership names a domain generation
  that never existed.
* A `REVALIDATION_REQUIRED` domain is currently restored to `CURRENT` only
  through `Registry::update_domain(transition = Current)`, which neither
  `PublisherClient` nor the publisher CLI exposes.
* Only the local host can be enumerated, and only for what the operating
  system exposes about its own devices. Physical infrastructure classification
  requires an authoritative inventory that this repository does not ship.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
