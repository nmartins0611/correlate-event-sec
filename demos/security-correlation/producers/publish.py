#!/usr/bin/env python3
"""Publish one scenario of synthetic security events to Kafka."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from kafka import KafkaProducer
from kafka.errors import KafkaError

JsonScalar = str | bool | int


class ScenarioError(ValueError):
    """The scenario name or flags do not match a known demo."""


class PublishError(RuntimeError):
    """Kafka did not accept a synthetic event."""


@dataclass(frozen=True)
class KafkaMessage:
    """One raw event and how long to wait before sending it."""

    topic: str
    body: Mapping[str, JsonScalar]
    pause_before_seconds: int


def encode_json(body: Mapping[str, JsonScalar]) -> bytes:
    """Encode one event as UTF-8 JSON."""
    return json.dumps(body, separators=(",", ":")).encode("utf-8")


def stolen_credential_messages(auth_only: bool) -> tuple[KafkaMessage, ...]:
    """Failed login, then a secret read for the same identity."""
    auth = KafkaMessage(
        topic="auth.failures",
        body={
            "event_id": "auth-1",
            "identity": "app-role-payments",
            "host": "api-1",
            "result": "failure",
            "ts": "2026-09-25T15:00:00Z",
        },
        pause_before_seconds=0,
    )
    if auth_only:
        return (auth,)
    vault = KafkaMessage(
        topic="vault.audit",
        body={
            "event_id": "vault-1",
            "identity": "app-role-payments",
            "path": "secret/data/payments",
            "operation": "read",
            "ts": "2026-09-25T15:03:00Z",
        },
        pause_before_seconds=0,
    )
    return (auth, vault)


def exposed_finding_messages(closed: bool) -> tuple[KafkaMessage, ...]:
    """Failed finding, then whether that port is still open."""
    port_open = False if closed else True
    return (
        KafkaMessage(
            topic="scanner.findings",
            body={
                "event_id": "scan-1",
                "host": "api-1",
                "cve": "CVE-2026-1000",
                "result": "Failed",
                "ts": "2026-09-25T15:10:00Z",
            },
            pause_before_seconds=0,
        ),
        KafkaMessage(
            topic="exposure.observations",
            body={
                "event_id": "exp-1",
                "host": "api-1",
                "cve": "CVE-2026-1000",
                "port_open": port_open,
                "ts": "2026-09-25T15:12:00Z",
            },
            pause_before_seconds=0,
        ),
    )


def change_messages(approved: bool) -> tuple[KafkaMessage, ...]:
    """A firewall change, optionally after an approval that covers it."""
    change = KafkaMessage(
        topic="changes.applied",
        body={
            "event_id": "chg-1",
            "host": "edge-1",
            "change": "firewall-rule-added",
            "actor": "sam",
            "ts": "2026-09-25T15:20:00Z",
        },
        pause_before_seconds=8 if approved else 0,
    )
    if not approved:
        return (change,)
    approval = KafkaMessage(
        topic="changes.approvals",
        body={
            "event_id": "apr-1",
            "host": "edge-1",
            "start": "2026-09-25T15:00:00Z",
            "end": "2026-09-25T16:00:00Z",
        },
        pause_before_seconds=0,
    )
    return (approval, change)


def break_in_messages(failures_only: bool) -> tuple[KafkaMessage, ...]:
    """Failures, then success, then egress from the same source and host."""
    failures = (
        KafkaMessage(
            topic="auth.attempts",
            body={
                "event_id": "try-1",
                "src_ip": "203.0.113.10",
                "host": "api-1",
                "account": "svc-api",
                "result": "failure",
                "ts": "2026-09-25T15:30:00Z",
            },
            pause_before_seconds=0,
        ),
        KafkaMessage(
            topic="auth.attempts",
            body={
                "event_id": "try-2",
                "src_ip": "203.0.113.10",
                "host": "api-1",
                "account": "svc-api",
                "result": "failure",
                "ts": "2026-09-25T15:30:30Z",
            },
            pause_before_seconds=0,
        ),
        KafkaMessage(
            topic="auth.attempts",
            body={
                "event_id": "try-3",
                "src_ip": "203.0.113.10",
                "host": "api-1",
                "account": "svc-api",
                "result": "failure",
                "ts": "2026-09-25T15:31:00Z",
            },
            pause_before_seconds=0,
        ),
    )
    if failures_only:
        return failures
    return (
        *failures,
        KafkaMessage(
            topic="auth.accepted",
            body={
                "event_id": "ok-1",
                "src_ip": "203.0.113.10",
                "host": "api-1",
                "account": "svc-api",
                "result": "success",
                "ts": "2026-09-25T15:32:00Z",
            },
            pause_before_seconds=0,
        ),
        KafkaMessage(
            topic="host.egress",
            body={
                "event_id": "out-1",
                "host": "api-1",
                "src_ip": "203.0.113.10",
                "dest_port": 443,
                "direction": "egress",
                "ts": "2026-09-25T15:33:00Z",
            },
            pause_before_seconds=0,
        ),
    )


def messages_for(
    scenario: str,
    auth_only: bool,
    closed: bool,
    approved: bool,
    failures_only: bool,
) -> tuple[KafkaMessage, ...]:
    """Return the raw events for one scenario."""
    if scenario == "stolen-credential":
        return stolen_credential_messages(auth_only)
    if scenario == "exposed-finding":
        return exposed_finding_messages(closed)
    if scenario == "change-outside-window":
        return change_messages(approved)
    if scenario == "break-in":
        return break_in_messages(failures_only)
    raise ScenarioError(f"Unknown scenario {scenario}")


def validate_flags(
    scenario: str,
    replay: bool,
    approved: bool,
    failures_only: bool,
    auth_only: bool,
    closed: bool,
) -> None:
    """Reject flag combinations that do not belong to the scenario."""
    if replay and scenario != "stolen-credential":
        raise ScenarioError("--replay is only valid for stolen-credential")
    if replay and auth_only:
        raise ScenarioError("--replay and --auth-only cannot be combined")
    if approved and scenario != "change-outside-window":
        raise ScenarioError("--approved is only valid for change-outside-window")
    if failures_only and scenario != "break-in":
        raise ScenarioError("--failures-only is only valid for break-in")
    if auth_only and scenario != "stolen-credential":
        raise ScenarioError("--auth-only is only valid for stolen-credential")
    if closed and scenario != "exposed-finding":
        raise ScenarioError("--closed is only valid for exposed-finding")
    selected = [approved, failures_only, auth_only, closed]
    if sum(1 for flag in selected if flag) > 1:
        raise ScenarioError("Choose only one negative-case flag")


def send_messages(bootstrap_servers: str, messages: Sequence[KafkaMessage]) -> None:
    """Send events in order. Raise if a record is not acknowledged."""
    producer = KafkaProducer(
        bootstrap_servers=bootstrap_servers,
        acks="all",
        retries=5,
        value_serializer=encode_json,
    )
    try:
        for message in messages:
            if message.pause_before_seconds > 0:
                time.sleep(message.pause_before_seconds)
            event_id = str(message.body["event_id"])
            try:
                metadata = producer.send(message.topic, value=message.body).get(timeout=30)
            except KafkaError as exc:
                raise PublishError(
                    f"Failed to publish {event_id} to {message.topic} via {bootstrap_servers}: {exc}"
                ) from exc
            print(
                f"published {message.topic} {event_id} partition={metadata.partition} offset={metadata.offset}",
                file=sys.stdout,
            )
        producer.flush()
    finally:
        producer.close()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse the scenario command."""
    parser = argparse.ArgumentParser(description="Publish synthetic security events")
    parser.add_argument(
        "scenario",
        choices=(
            "stolen-credential",
            "exposed-finding",
            "change-outside-window",
            "break-in",
        ),
    )
    parser.add_argument("--bootstrap-servers", default="localhost:9092")
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--approved", action="store_true")
    parser.add_argument("--failures-only", action="store_true")
    parser.add_argument("--auth-only", action="store_true")
    parser.add_argument("--closed", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    """Publish one scenario and return a process status."""
    args = parse_args(argv)
    try:
        validate_flags(
            args.scenario,
            args.replay,
            args.approved,
            args.failures_only,
            args.auth_only,
            args.closed,
        )
        payload = messages_for(
            args.scenario,
            args.auth_only,
            args.closed,
            args.approved,
            args.failures_only,
        )
        send_messages(args.bootstrap_servers, payload)
    except (ScenarioError, PublishError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
