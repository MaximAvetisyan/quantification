# Kubernetes

`quantification.yaml` holds a `Deployment` and a `Service` for the image the
root `Dockerfile` builds.

## `replicas: 1` bounds steady state. It does not make restore consistent

This is the first thing to know about this manifest, so it is first.

The CCR store is **per-pod and in-process**. `ccr::Shared` is an
`Arc<Mutex<Store>>` living inside the server binary, with a 15-minute TTL and a
64 MiB bound, and nothing writes it to disk or to any shared backend. A
`restore_id` — `lower-hex(xxh3-128(span)) ":" decimal(byte_length)`, normative
in DESIGN.md §9 — therefore resolves **only on the pod that produced it**.

With `replicas: 2`, a `POST /v1/restore` that lands on the other replica
returns `404 not_found` for an id this server issued seconds earlier. The id is
not malformed and the client did nothing wrong; the replica answering simply
never saw the compress. So the manifest ships `replicas: 1`.

Read precisely, that buys **steady-state** correctness: at rest, one pod
answers, so a compress and its restore cannot be split. It is not a guarantee,
and the rest of this section is about the ways it is not one.

### What `replicas: 1` does not do

It does **not** protect a restore across a rollout, and the intuitive version
of the claim is wrong in a way worth being blunt about.

`strategy: RollingUpdate` with `maxSurge: 1, maxUnavailable: 0` guarantees the
old and the new pod **run simultaneously**. `maxUnavailable: 0` is exactly why:
the incumbent is not terminated until the replacement is Ready, and the
replacement's readiness is *its own* `/readyz`, which says nothing whatever
about the incumbent's store. So for the whole duration of a deploy — and
equally of a node drain or an eviction — there is a window containing **two
Ready pods, both in the Service endpoints, each with its own empty store**, and
a request goes to whichever one the dataplane picks.

A compress that lands on one and a restore that lands on the other is exactly
the `404` above, reintroduced on every single deploy. `replicas: 1` drives the
steady-state probability of that to zero and leaves the per-deploy probability
exactly where a two-replica deployment would have it. It was never buying
rollout safety.

That is inherent to an in-process store at any replica count, and **no replica
count and no `strategy` field fixes it** — the pod that holds the entry is the
pod that dies. The two recipes that come closest, and their costs, are in *Two
ways to get real consistency* below.

### What a `404` from `/v1/restore` actually means

A restore miss has **two legitimate causes**, and the response body cannot
distinguish them — it says `no stored span for restore_id <id>` either way:

1. the id expired (15-minute TTL) or was evicted (64 MiB bound); **or**
2. the compress and the restore landed on different pods, during a rollout, a
   node drain or an eviction.

So `404` is **not** the assertion "this id never existed", and callers must not
read it as one. Treat a restore miss as **non-fatal and retryable**: the
compressed payload is fully usable without the original, because compression
is lossy by design and its output is the deliverable. The correct client
behaviour is to log the miss, proceed with the compressed bytes, and treat the
original as recoverable only by re-compressing from source. A `404` is not a
data-integrity signal and must not fail a request that only needed the
compressed form.

### Two ways to get real consistency

1. **`strategy: {type: Recreate}`** — manifest-only, and the only manifest-only
   option that removes the window. The old pod is fully terminated before the
   new one is created, so there is no instant at which two stores are in
   service and a live compress/restore pair cannot be split by the rollout.

   ```yaml
   spec:
     replicas: 1
     strategy:
       type: Recreate
   ```

   Delete the `rollingUpdate:` block entirely — it is only meaningful for
   `RollingUpdate` and the API server rejects a `Recreate` that still carries
   it.

   Its honest cost: the Service has **no endpoints at all** for the whole
   replacement, from the moment the old pod is deleted until the new one is
   Ready. Clients get connection refused, not a `404`, for that window, on
   every deploy. Do not overstate the window, though — most of it is the new
   pod's start-up, not the old pod's death: the server's drain is a ~2 s settle
   plus in-flight work, so an idle pod exits in seconds and
   `terminationGracePeriodSeconds: 30` is a *ceiling* the kubelet waits out
   rather than a wait it performs. The pathological upper bound is that 30 s
   plus the startup probe's `15 x 2 s`. For a compression service, whose whole
   design premise is that it is "safe to skip", trading a rare `404` on a
   secondary endpoint for a guaranteed hole in the primary on every deploy is
   the worse default — which is why this manifest ships `RollingUpdate`.

   Two limits worth stating: it is **correct only because `replicas: 1`** — at
   two replicas `Recreate` tears down *all* the pods, so you get the same
   downtime and none of the benefit, since the overlap it removes is the only
   thing it removes. And it still does **not** preserve an id across the deploy
   boundary itself: the replacement's store starts empty, so an id minted
   before the deploy `404`s after it. No strategy can fix that; only a store
   that outlives the process can.

2. **Move the store out of process** — the real fix. Implement
   `quantification_server::RestoreStore` against a shared cache (Redis, or a
   sidecar) instead of `ccr::Shared`, keeping the id format and the
   re-verification contract in DESIGN.md §9 exactly as they are. Then any
   replica can answer for any id, `replicas` becomes a free scaling knob again,
   and neither `Recreate` nor the steady-state pin is needed.

   This is a code change, not a manifest change, and it is the only option
   that keeps `/v1/restore` correct across a pod restart at all.

**Which to pick.** Keep the shipped `RollingUpdate` + `replicas: 1` unless you
have measured that restore misses actually hurt you — the compressed output is
the product, and the miss costs you the original, not the response. If a
specific client needs compress-then-restore on opposite sides of a deploy,
switch that deployment to `Recreate` and accept the deploy downtime. If restore
is load-bearing, skip both and do the out-of-process store: it is the only one
of the three that is a fix rather than a trade, and it is a small change
against a trait that already exists for exactly this purpose.

### Scaling past one pod

Compression itself is stateless and scales without limit. Only restore needs
pinning. To run more than one pod, the store has to be out of process, or:

**`sessionAffinity: ClientIP` on the Service**, with `replicas: 2`. Each client
IP is pinned to one pod, so one client's own compress/restore pair reaches one
store. This is manifest-only and it is a weaker guarantee, which is why it is
not the default here: it holds only while the whole restore flow arrives from
a single source IP. A client behind NAT, behind a proxy, or running a gRPC
connection pool across several egress IPs spans multiple IPs, gets split
across pods, and 404s exactly as before. And it is stickiness to one IP, not
a load-balancing strategy: one unlucky IP owns one pod's entire share. It also
does not survive a rollout, for the same reason `replicas: 1` does not — the
pinned pod is replaced and the new one's store is empty.

If neither is in place, keep `replicas: 1`.

### Two consequences of a single replica that are worth stating plainly

* **No HA.** The pod going away is the service going away, and at `replicas: 1`
  there is nothing to fail over to.

  What is actually here is `maxSurge: 1`, and it is worth being precise about
  what it buys, because it is easy to over-credit: it keeps a **planned
  rollout** serving continuously (the replacement is Ready before the
  incumbent is terminated) and it limits the `Recreate`-style hard stop, but it
  does **not** help a crash. When a pod is already gone there is nothing left
  to surge ahead of — the ReplicaSet simply schedules a replacement, and the
  outage is however long that pod takes to start. A container that exits
  without the kubelet noticing is likewise restarted in place, with the same
  re-listen cost and no surge at all.

  There is deliberately **no `PodDisruptionBudget`**, and at `replicas: 1` one
  would be inert or harmful. A PDB constrains only *voluntary* disruption; with
  a single replica `minAvailable: 1` makes the eviction API refuse every
  voluntary eviction, so a node drain hangs rather than proceeding, and any
  value below 1 constrains nothing the manifest does not already permit. The
  disruptions that actually end a one-replica pod — a crash, a liveness
  restart, an involuntary eviction — are outside a PDB's reach entirely. If
  you move the store out of process and run two or more pods, add one then,
  where it has something to protect.
* **Restore ids do not survive a rollout, at any replica count.** A rolling
  update, node drain or eviction replaces the process and the store starts
  empty. See *Two ways to get real consistency* for what does and does not fix
  that, and *What a 404 actually means* for how a client should respond.

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

`readinessProbe` is `periodSeconds: 1, failureThreshold: 1`, i.e. the kubelet
marks the pod NotReady on the first probe that observes the `503`. That probe
is up to one period away, so the honest budget is **not** the full 2 s:

```
SIGTERM ── 503 ── up to ~1000 ms ── probe observes ── ~1000 ms ── listener closes
                       (kubelet cannot know yet)      (dataplane propagation)
```

The first second of the settle is spent waiting for the kubelet to *find out*
that the pod went unready; what remains for the endpoint change to propagate
through kube-proxy and the node's iptables is roughly the second second. So
budget ~1 s of propagation, not 2 s, and remember the settle is a fixed timer
rather than a wait-for-completion signal: the server has no way to observe
whether the dataplane has caught up, and a client already in flight when the
listener closes gets connection refused. That is the failure the whole design
is trying to avoid, since compression is meant to be safe to skip and this one
is not — the tighter probe narrows the window, it does not close it.

The previous values, `periodSeconds: 5, failureThreshold: 3`, left that window
at up to ~15 s against a ~2 s drain, so most of it was pure exposure.

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

### `progressDeadlineSeconds: 120`

Set explicitly, because the default is 600 s. A rollout only "progresses" when
the new pod gets past its startup probe and reports Ready; if it cannot — a bad
image tag, `ImagePullBackOff`, a probe path that does not answer — the
Deployment controller has nothing to advance and waits out the deadline before
marking the rollout failed. At the default that is **ten minutes** of a
half-applied deploy nobody has been told about. 120 s surfaces the same failure
in two minutes.

It is an observability speed, not an availability setting: with
`maxUnavailable: 0` the incumbent keeps serving throughout, and the stuck
ReplicaSet keeps retrying past the deadline. Nothing is rolled back; the
deadline only turns silence into a `Failed` condition and an event. Pick a
value comfortably above the worst legitimate start-up — the startup probe
allows `15 x 2 s` here, so 120 s leaves several times that — and remember it
must also exceed any image pull time for the new tag.

## Contract this manifest assumes

* **Non-root UID/GID 65532, numerically.** The runtime stage is
  `gcr.io/distroless/cc-debian12` and the Dockerfile says `USER 65532:65532`.
  The numbers are the contract, not the name: a `USER` naming a user is only
  resolvable if that user exists in the image's `/etc/passwd`, and whether
  `gcr.io/distroless/cc-debian12` carries a `nonroot` entry is not something
  this tree can verify, since the image has never been built here. The
  manifest sets `runAsUser`/`runAsGroup: 65532` to the same values, so a pod
  is non-root either way — and `runAsNonRoot: true` will reject the container
  outright if the effective UID ever turns out to be 0.
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
  the pod that produced it. This is why `replicas: 1` — and why a `404` from
  `/v1/restore` is a non-fatal, retryable miss rather than proof the id never
  existed. See the top of this file.

## Validation status

The image was **not built** in the environment this manifest was written in,
and that is still true: no container registry is reachable from this machine
(`docker pull rust:1.98-bookworm` still fails with `net/http: TLS handshake
timeout`), so neither base image can be fetched and no image is produced here.
Nothing in this change alters that — the probe timings, drain budgets and
store-affinity claims above are read off the source in this tree, not observed
on a running pod.

What *has* changed is that the Dockerfile is no longer only reviewed. The `image`
job in `.github/workflows/ci.yml` runs `docker build` and a `docker run`
smoke test on every push to `master` and every pull request, and GitHub's
runners do have working registry access, so that job is the first thing that
will ever actually assemble this image and the first evidence that the numeric
`USER 65532:65532` resolves. Until it has been green, treat the image as
unbuilt — but no longer as never-executed.

What was verified for the manifest itself here is structural only: the YAML
parses as two documents, and the Deployment's selector matches its pod template
labels, the Service's selector matches them too, every probe's `port` names a
declared container port, every `targetPort` names a Service port that maps to
the matching container port, and `terminationGracePeriodSeconds` still exceeds
`QUANT_SHUTDOWN_GRACE_MS`. `kubectl`, `kubeconform` and `yamllint` are **not
installed on this machine**, so no schema validation and no server-side dry run
happened; treat the manifest as reviewed-but-unapplied — including the drain
behaviour, which has never been observed under a real kubelet — until someone
runs the build above and applies it.
