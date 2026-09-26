# Security correlation

Synthetic security events land in Kafka. Apache Flink correlates each scenario into one incident on `security.incidents`. `ansible-rulebook` reads only that topic and records one local action. Replaying the same incident does not record it again.

```text
producers -> raw Kafka topics -> Flink job -> security.incidents -> ansible-rulebook -> action log
```

Flink runs on its own host. It is not installed in the decision environment. The rulebook does not read raw topics and does not join events again. Producers publish synthetic JSON only. The action appends one JSON line to `/tmp/security-demo/actions.jsonl` on the target. It does not call a firewall, an identity provider, or Vault.

Kafka in this lab has no authentication. The broker listener is plaintext and the firewall rule allows only `192.168.88.0/24`. Do not expose port 9092 beyond that lab network.

## Lab

| Role | Host | Address |
|---|---|---|
| Automation controller and EDA | `aap.nostromo.io` | `192.168.88.163` |
| Kafka and Flink | `rhel02.nostromo.io` | `192.168.88.103` |
| Action target | `rhel01.nostromo.io` | `192.168.88.121` |

`incident_id` is the MD5 hex digest of `kind`, `correlation_key`, and the source event ids joined with `|`. Stolen-credential and exposed-finding sort those ids. Break-in keeps match order: three failures, the success, then egress.

Install the streaming side on rhel02:

```sh
cd demos/security-correlation
ansible-playbook -i inventories/lab.yml playbooks/site-streaming.yml
```

That runs `setup-kafka.yml`, `setup-topics.yml`, and `setup-flink.yml` in order. Java is Temurin 17 from Adoptium, because this host's Red Hat CDN currently returns 403 for the OpenJDK RPMs. Kafka is 3.9.1 in KRaft mode. Flink is 1.19.3.

Publish one scenario from a machine that can reach the broker:

```sh
python -m venv .venv
.venv/bin/pip install -r producers/requirements.txt
.venv/bin/python producers/publish.py stolen-credential --bootstrap-servers 192.168.88.103:9092
```

Run the rulebook in the decision-environment image. It has `ansible-rulebook`, `aiokafka`, and Java. The action is written on rhel01. Mount an SSH key that can log in as root there.

```sh
podman build -t security-correlation-rulebook -f Dockerfile .
podman run --rm --network host --user 0 \
  --security-opt label=disable \
  -v "$PWD:/demo:ro" \
  -v "${HOME}/.ssh/id_ed25519:/ssh/id_ed25519:ro" \
  -e ANSIBLE_HOST_KEY_CHECKING=False \
  -e ANSIBLE_PRIVATE_KEY_FILE=/ssh/id_ed25519 \
  -w /demo \
  localhost/security-correlation-rulebook \
  ansible-rulebook \
  -r /demo/rulebooks/security-incidents.yml \
  -i /demo/inventories/lab.yml \
  -e /demo/vars/lab.yml \
  --print-events
```

On AAP (`https://aap.nostromo.io/`), the activation uses the repository-root rulebook `rulebooks/security-incidents-aap.yml` and launches the controller job template `Security correlation record action`. That template runs `playbooks/record-action.yml` against the `targets` group with the OT lab machine credential. Activation variables are `kafka_host` and `kafka_port` from `vars/lab.yml`. The activation must reach `192.168.88.103:9092`. The direct rulebook in `security-incidents.yml` stays for the local decision-environment image, which includes the hoist filter.

Confirm the action log on rhel01:

```sh
ssh root@192.168.88.121 cat /tmp/security-demo/actions.jsonl
```

Negative cases and replay:

```sh
.venv/bin/python producers/publish.py stolen-credential --bootstrap-servers 192.168.88.103:9092 --replay
.venv/bin/python producers/publish.py stolen-credential --bootstrap-servers 192.168.88.103:9092 --auth-only
.venv/bin/python producers/publish.py exposed-finding --bootstrap-servers 192.168.88.103:9092
.venv/bin/python producers/publish.py exposed-finding --bootstrap-servers 192.168.88.103:9092 --closed
.venv/bin/python producers/publish.py change-outside-window --bootstrap-servers 192.168.88.103:9092
.venv/bin/python producers/publish.py change-outside-window --bootstrap-servers 192.168.88.103:9092 --approved
.venv/bin/python producers/publish.py break-in --bootstrap-servers 192.168.88.103:9092
.venv/bin/python producers/publish.py break-in --bootstrap-servers 192.168.88.103:9092 --failures-only
```

`--replay` publishes the same stolen-credential ids again and must not append a second action line. `--auth-only`, `--closed`, `--approved`, and `--failures-only` must not create an incident or an action line. Run `--approved` only after the positive change test, on a broker that does not already contain that approval, or the later positive change will see the approval and stay quiet.

## Local compose

Compose runs the same pipeline on one machine. Containers use the Kafka listener advertised as `broker:9092`. The host producer uses `localhost:9092`.

```sh
cd demos/security-correlation
docker compose up -d --build
python producers/publish.py stolen-credential
docker compose logs -f rulebook
```

Repeat for `exposed-finding`, `change-outside-window`, and `break-in`. Then run the matching replay or negative flag and confirm `/tmp/security-demo/actions.jsonl` inside the rulebook container.
