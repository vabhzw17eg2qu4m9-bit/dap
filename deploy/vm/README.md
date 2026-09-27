# dap hub on a single GCE VM — runbook

Vertical-scaling hosting target from [issue #4](https://github.com/vabhzw17eg2qu4m9-bit/dap/issues/4):
one Container-Optimized OS VM, docker compose with `caddy:2` (TLS for
hub.fa1.dev via Let's Encrypt) and the hub image `ghcr.io/vabhzw17eg2qu4m9-bit/dap:latest`
(published by `.github/workflows/ci.yml`; the Cloud Run workflow builds the
same hub from `hub/` via `--source`). Scaling = a bigger machine, never a
redesign: one-conn-per-agent registry, in-memory mailboxes and presence are
single-process by design. Boring on purpose — no Terraform, no extra deps.

State model: `channels.json` + `secrets.json` live in `/data` inside the hub
container, bind-mounted from `/var/lib/dap` on the persistent boot disk. They
survive container restarts and VM stop/start. In-memory mailboxes and
presence do NOT (same as Cloud Run today — not a regression, edge case E4).

Acceptance criteria covered: **AC3** (steps 1–5), **AC4** (step 6),
**AC5** (step 7). Live execution of AC3/AC4/AC5 is an owner op.

## 1. Provision the VM + static IP (one-time)

```sh
gcloud compute addresses create dap-hub-ip --region=us-central1
gcloud compute instances create dap-hub \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-project=cos-cloud --image-family=cos-stable \
  --boot-disk-size=10GB \
  --address=dap-hub-ip \
  --tags=dap-hub
gcloud compute firewall-rules create allow-dap-hub \
  --allow=tcp:80,tcp:443 --target-tags=dap-hub
# keep ssh reachable however the project already manages it
```

The static IP survives stop/start and is the DNS target. (Billing note: the
e2-micro fits Always Free; the static IPv4 is billable while reserved —
open question from the card, owner decision.)

## 2. First deploy

```sh
gcloud compute scp docker-compose.yml Caddyfile dap-hub:~/dap --zone=us-central1-a
gcloud compute ssh dap-hub --zone=us-central1-a
  # on the VM:
  sudo mkdir -p /var/lib/dap /etc/dap
  sudo chown 65532:65532 /var/lib/dap        # distroless hub runs as uid 65532
  sudo sh -c 'printf "HUB_MASTER_SECRET=%s\nHUB_ADMIN_TOKEN=%s\n" \
    "$(openssl rand -base64 32)" "$(openssl rand -hex 16)" > /etc/dap/hub.env'
  sudo chmod 600 /etc/dap/hub.env
  # paste the real master secret (the one fa_network already holds) — rotate
  # nothing; secrets must never travel through shell history: edit the file
  # instead of inlining the value on a command line (edge case E3)
  cd ~/dap && sudo docker compose up -d
  curl -s http://localhost/healthz -H 'Host: hub.fa1.dev'  # via caddy, pre-TLS
```

Caddy obtains the certificate once DNS points here (step 4); it retries
ACME until then (edge case E5).

## 3. Sync state from the Cloud Run GCS volume

The Cloud Run deployment mounts `gs://dap-hub-data` at `/data`. Copy the
state down and onto the VM so enrolled agents and channels carry over
(precondition for AC5's "without data loss"):

```sh
gsutil cp gs://dap-hub-data/channels.json gs://dap-hub-data/secrets.json .
gcloud compute scp channels.json secrets.json dap-hub:~/ --zone=us-central1-a
# on the VM:
sudo mv ~/channels.json ~/secrets.json /var/lib/dap/
sudo chown 65532:65532 /var/lib/dap/*.json
sudo docker compose -f ~/dap/docker-compose.yml restart hub
```

`secrets.json` holds sha256 hashes only, but treat the file as sensitive
anyway (0600-style discipline; a leaked secret is rotated by re-enrolling).

## 4. DNS cutover

Point the `hub.fa1.dev` A record at the reserved address (`gcloud compute
addresses describe dap-hub-ip --region=us-central1 --format=value(address)`).
Lower TTL beforehand if the zone allows it. Wait for propagation — Caddy
completes ACME — then verify:

```sh
curl -s https://hub.fa1.dev/healthz
```

## 5. Live probe (AC3 — owner op)

Enroll an agent via fa_network (`POST /api/networks/{id}/agents/enroll`),
connect with `DAP_CLIENT_SECRET` + the enrolled name to `wss://hub.fa1.dev/ws`,
join a pre-created channel, exchange an E2E message with the fa_network
relay. The service counts as live only after this passes (edge case E5).

## 6. Vertical resize (AC4)

```sh
gcloud compute instances stop dap-hub --zone=us-central1-a
gcloud compute instances set-machine-type dap-hub \
  --machine-type=e2-small --zone=us-central1-a   # or e2-medium / e2-standard-4
gcloud compute instances start dap-hub --zone=us-central1-a
```

`restart: unless-stopped` brings compose back at boot; no code or topology
change. Verify `channels.json`/`secrets.json` survived (repeat the AC3
probe; hub answers with identical data). Expected during the stop: the
in-memory mailboxes and presence are lost — same as Cloud Run with
`--min-instances 0` today (edge case E4).

## 7. Rollback to Cloud Run (AC5)

Cloud Run stays deployed and scaled-to-0 (`--min-instances 0`):

```sh
# sync state back (from the workstation, like step 3) so nothing enrolled
# on the VM is lost
gcloud compute scp dap-hub:/var/lib/dap/channels.json dap-hub:/var/lib/dap/secrets.json . \
  --zone=us-central1-a --scp-flag=sudo
gsutil cp channels.json secrets.json gs://dap-hub-data/
# flip DNS back to the Cloud Run endpoint (domain mapping as before)
```

Cloud Run picks up the restored files from the GCS volume on its next
instance; service restores without data loss.

## 8. Disk snapshots

```sh
gcloud compute resource-policies create-snapshot-schedule dap-hub-daily \
  --region=us-central1 --max-retention-days=14 \
  --daily-schedule --start-time=04:00
gcloud compute disks add-resource-policies dap-hub \
  --resource-policies=dap-hub-daily --zone=us-central1-a
```

Cadence is an open question from the card (daily ≈ cents/month — owner
confirms).

## Open questions (from the card, owner ops)

- Static external IPv4 billing (~$3.6/mo on top of the free-tier VM) vs.
  proxied-DNS-to-ephemeral-IP automation.
- Snapshot cadence (daily proposed above).
