# Kubernetes

`quantification.yaml` holds a `Deployment` and a `Service` for the image the
root `Dockerfile` builds.

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
* **Probes need no in-image tooling.** Both are `httpGet`, which the kubelet
  performs itself, so the image needs neither `curl` nor `wget` — which is why
  the Dockerfile has no `HEALTHCHECK` (a shell-based one could not run in a
  shell-less image anyway) and the runtime stage has no shell.
* **`/healthz` and `/readyz` are unconditional `200`s.** They are static
  responses; they do not probe the gRPC listener or the store. They detect a
  wedged event loop, not a broken dependency.
* **SIGTERM.** `STOPSIGNAL SIGTERM` matches what the kubelet sends on pod
  deletion. `terminationGracePeriodSeconds: 30` is set so the process has time
  to drain in-flight requests; keep it at or above whatever drain grace the
  binary is built with.
* **Memory.** The memory limit must cover the 64 MiB `request_body_limit` plus
  the core's span-sized working set; 1Gi is the floor, not a measurement.
* **The CCR store is per-pod.** `ccr::Shared` is an in-process
  `Arc<Mutex<Store>>` with a 15-minute TTL, so a `restore_id` only resolves on
  the pod that produced it. With `replicas: 2` a `POST /v1/restore` can reach a
  pod that never saw the compress and get `404`. Compression itself is
  stateless and scales fine. If you depend on `/v1/restore`, either set
  `replicas: 1` or add `sessionAffinity: ClientIP` to the Service.

## Validation status

The image was **not built** in the environment this manifest was written in:
no container registry was reachable (every pull attempt failed with
`net/http: TLS handshake timeout`), so neither base image could be fetched and
no image was produced. What *was* done is in the commit message for the
Dockerfile: every build step was run natively, the release binary was started
and exercised over real sockets, and `ldd` was run on it. Treat the manifest as
reviewed-but-unapplied until someone runs the build above.
