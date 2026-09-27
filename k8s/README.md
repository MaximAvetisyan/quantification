# Kubernetes

`quantification.yaml` holds a `Deployment` and a `Service` for the image the
root `Dockerfile` builds.

## `replicas: 1` is a correctness constraint, not a scaling choice

This is the first thing to know about this manifest, so it is first.

The CCR store is **per-pod and in-process**. `ccr::Shared` is an
`Arc<Mutex<Store>>` living inside the server binary, with a 15-minute TTL and a
64 MiB bound, and nothing writes it to disk or to any shared backend. A
`restore_id` — `lower-hex(xxh3-128(span)) ":" decimal(byte_length)`, normative
in DESIGN.md §9 — therefore resolves **only on the pod that produced it**.

With `replicas: 2`, a `POST /v1/restore` that lands on the other replica
returns `404 not_found` for an id this server issued seconds earlier. The id is
not malformed and the client did nothing wrong; the replica answering simply
never saw the compress. The manifest must not ship a configuration where a
documented endpoint returns `404` for a valid id, so it ships `replicas: 1`.

Compression itself is stateless and scales without limit. Only restore needs
pinning. Two supported ways to run more than one pod, and only two:

1. **Move the store out of process.** The real fix: back `RestoreStore` with a
   shared cache (Redis, or a sidecar) rather than `ccr::Shared`, and any replica
   can answer for any id. This is a code change, not a manifest change, and it
   is the only option that keeps `/v1/restore` correct across pod restarts.
2. **Sticky routing — `sessionAffinity: ClientIP` on the Service**, with
   `replicas: 2`. Each client IP is pinned to one pod, so one client's own
   compress/restore pair reaches one store. This is manifest-only, and it is a
   weaker guarantee than option 1, which is why it is not the default here: it
   holds only while the whole restore flow arrives from a single source IP. A
   client behind NAT, behind a proxy, or running a gRPC connection pool across
   several egress IPs spans multiple IPs, gets split across pods, and 404s
   exactly as before. And it is stickiness to one IP, not a load-balancing
   strategy: one unlucky IP owns one pod's entire share.

If neither is in place, keep `replicas: 1`.

Two consequences of a single replica that are worth stating plainly rather than
discovering:

* **No HA.** The pod going away is the service going away. Mitigations are the
  kubelet's own restart of a liveness-failing container, a `PodDisruptionBudget`,
  and `maxSurge: 1` (set here), which brings the replacement up before the
  incumbent is terminated.
* **Restore ids do not survive a rollout.** Even on one replica, a rolling
  update, node drain or eviction replaces the process and the store starts
  empty, so an id held across one returns `404`. That is inherent to an
  in-process store at any replica count and is not fixable in this manifest.

## Build and push

From the repository root, with registry access:

```sh
docker build -t $REGISTRY/quantification:0.1.0 . && docker push $REGISTRY/quantification:0.1.0
```

## Deploy

Point the Deployment's `image` at what you pushed, then:

```sh
kubectl apply -f k8s/quantification.yaml
```

`image: quantification:0.1.0` in the manifest is a local tag; a cluster cannot
pull it unless the image is in the node's local store.

## The drain, and why the readiness probe is tuned the way it is

On `SIGTERM` the server does three things in order (`crates/server/src/main.rs`,
`crates/server/src/lib.rs`):

1. flips `/readyz` to `503 {"status":"draining"}` — immediately, before anything
   else;
2. waits out an **endpoint settle** of `min(QUANT_SHUTDOWN_GRACE_MS / 4, 2000)`
   ms, so the dataplane has time to act on the readiness change;
3. releases the graceful-shutdown signal, which stops accepting and lets
   in-flight HTTP and gRPC requests finish, bounded by the full
   `QUANT_SHUTDOWN_GRACE_MS`.

So at the manifest's `QUANT_SHUTDOWN_GRACE_MS: "25000"`, the settle is
`min(6250, 2000)` = **2000 ms** and the listener closes ~2 s after the signal.

`readinessProbe` is therefore `periodSeconds: 1, failureThreshold: 1`, i.e. the
pod is marked NotReady within one probe period of the flip. That is what makes
step 2's window sufficient: the endpoint removal the settle exists to buy has
already happened before the listener goes away.

The previous values, `periodSeconds: 5, failureThreshold: 3`, gave a NotReady
pod up to ~15 s to leave the Service endpoints, while the listener was gone
after ~2 s. A client in that window was not routed away — it got connection
refused, which is the failure the whole design is trying to avoid, since
compression is meant to be safe to skip and this one is not.

### Do not add a `preStop` sleep hook

It is the obvious "fix" and it is wrong here, in a way that is easy to argue
yourself into.

A `preStop` hook runs **before** `SIGTERM`, and during it the pod is still
Ready. Sleeping in `preStop` does not remove the pod from Service endpoints; it
only delays the signal. Since the drain clock, the `503` flip and the settle
window all start at `SIGTERM`, a preStop sleep buys nothing the binary's own
settle does not already do — and it actively costs: it spends part of
`terminationGracePeriodSeconds` on a wait, and it pushes the signal later, so
the settle window ends later in wall-clock terms after the pod was marked for
deletion. The correct mechanism for this workload is the one the binary already
implements — a readiness state that changes on the signal, then a timed settle —
and the manifest's job is only to probe it fast enough to fit.

### `terminationGracePeriodSeconds: 30` must stay above the drain grace

`QUANT_SHUTDOWN_GRACE_MS` is set explicitly in the container env so it is
auditable in the manifest instead of being whatever the binary happens to be
built with. The kubelet starts `terminationGracePeriodSeconds` at the moment
termination begins — and with no `preStop` hook, that is the `SIGTERM` — so
the two are directly comparable and the relationship is:

```
terminationGracePeriodSeconds  >  QUANT_SHUTDOWN_GRACE_MS
              30               >        25000 ms
```

The headroom exists so the process can finish its budget, exit 0 and be torn
down before the kubelet reaches for `SIGKILL`.

If an operator sets `terminationGracePeriodSeconds` **at or below** the drain
grace, the process is `SIGKILL`ed before its own budget expires. The pod still
leaves the endpoints correctly — that still works — but the graceful path never
completes: in-flight requests are severed mid-response and the server never gets
to report its own `in-flight work outlived the grace period` (exit code 2).
Lowering the grace instead of the grace period is the correct direction if you
need a shorter teardown; keep the period above whatever grace you set.

## Contract this manifest assumes

* **Non-root UID 65532.** The runtime stage is `gcr.io/distroless/cc-debian12`
  and runs as the distroless `nonroot` user, which is UID/GID 65532 in that
  image's `/etc/passwd`. The manifest sets `runAsUser`/`runAsGroup: 65532` to
  match, so the pod is non-root even if the image's `USER` line is ever
  dropped.
* **`readOnlyRootFilesystem: true` is safe.** `quantification-core` and
  `quantification-server` contain no filesystem writes at all: no `std::fs`,
  no `File::create`, no `OpenOptions`, no temp files, no config file, no
  logging to disk. Metrics are an in-process `BTreeMap`. The only `std::fs` use
  in the tree is in `quantification-eval` and in `tests/`/`benches/`, none of
  which are linked into the server binary.
* **Probes need no in-image tooling.** All three are `httpGet`, which the
  kubelet performs itself, so the image needs neither `curl` nor `wget` — which
  is why the Dockerfile has no `HEALTHCHECK` (a shell-based one could not run
  in a shell-less image anyway) and the runtime stage has no shell.
* **`/healthz` is an unconditional `200` `{"status":"ok"}`, and it must stay
  one.** It is the liveness probe, and liveness deliberately does **not** go
  unhealthy during a drain: if it did, the kubelet would conclude the container
  is wedged and restart it while it is still finishing in-flight requests,
  which is precisely what the drain exists to avoid. It detects a wedged event
  loop, not a broken dependency, and does not probe the gRPC listener or the
  store.
* **`/readyz` is `200` `{"status":"ready"}` normally, and `503`
  `{"status":"draining"}` from the instant of the signal until the process
  exits.** The `503` is deliberate and is load-bearing, not a cosmetic state
  change: a failing readiness probe is the only thing that removes a pod from
  Service endpoints. Returning `200` with a `{"status":"draining"}` body would
  read as ready, the pod would keep receiving traffic, and the settle window
  would be spent waiting for an event that never happens. It is also the only
  probe wired to drain state; `/healthz` and `/metrics` are unaffected.
* **SIGTERM.** `STOPSIGNAL SIGTERM` in the image matches what the kubelet sends
  on pod deletion, and `crates/server/src/main.rs` installs a `SIGTERM` and
  `SIGINT` handler, so the drain is reachable in the cluster. See
  *The drain* above for the timings and the
  `terminationGracePeriodSeconds > QUANT_SHUTDOWN_GRACE_MS` relationship.
* **Memory.** The memory limit must cover the 64 MiB `request_body_limit` plus
  the core's span-sized working set; 1Gi is the floor, not a measurement.
* **The CCR store is per-pod.** `ccr::Shared` is an in-process
  `Arc<Mutex<Store>>` with a 15-minute TTL, so a `restore_id` only resolves on
  the pod that produced it. This is why `replicas: 1` — see the top of this
  file.

## Validation status

The image was **not built** in the environment this manifest was written in:
no container registry was reachable (every pull attempt failed with
`net/http: TLS handshake timeout`), so neither base image could be fetched and
no image was produced. That is still true, and nothing in this change alters
it — the probe timings, drain budgets and store-affinity claims below are read
off the source in this tree, not observed on a running pod. What *was* done is
in the commit message for the Dockerfile: every build step was run natively,
the release binary was started and exercised over real sockets, and `ldd` was
run on it.

What was verified for the manifest itself is structural: the YAML parses, and
the Deployment's selector matches its pod template labels, the Service's
selector matches them too, every probe's `port` names a declared container port,
and every `targetPort` names a Service port that maps to the matching container
port. Treat the manifest as reviewed-but-unapplied — including the drain
behaviour, which has never been observed under a real kubelet — until someone
runs the build above and applies it.
