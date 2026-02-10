#!/usr/bin/env python3
"""
Generate synthetic authentication logs for a security AI PoC.

Output:
  poc-auth-anomaly/data/sample_auth_logs.csv

Notes:
- Data is synthetic and safe for public repos.
- Includes both normal behavior and injected anomalies.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass(frozen=True)
class UserProfile:
    username: str
    home_country: str
    usual_hours: Tuple[int, int]  # inclusive start hour, inclusive end hour
    success_rate: float
    known_ip_blocks: List[str]  # CIDR blocks


def weighted_choice(rng: random.Random, items: List[Tuple[str, float]]) -> str:
    total = sum(w for _, w in items)
    r = rng.random() * total
    upto = 0.0
    for item, weight in items:
        upto += weight
        if upto >= r:
            return item
    return items[-1][0]


def random_ip_from_cidr(rng: random.Random, cidr: str) -> str:
    net = ipaddress.ip_network(cidr, strict=False)
    # avoid network/broadcast for IPv4 where applicable
    if isinstance(net, ipaddress.IPv4Network) and net.num_addresses > 2:
        first = int(net.network_address) + 1
        last = int(net.broadcast_address) - 1
    else:
        first = int(net.network_address)
        last = int(net.network_address) + net.num_addresses - 1
    return str(ipaddress.ip_address(rng.randint(first, last)))


def random_timestamp(rng: random.Random, start: datetime, end: datetime, prefer_hours: Tuple[int, int] | None) -> datetime:
    total_seconds = int((end - start).total_seconds())
    base = start + timedelta(seconds=rng.randint(0, total_seconds))

    if prefer_hours is None:
        return base

    h_start, h_end = prefer_hours
    # 80% of the time, force hour into the preferred window
    if rng.random() < 0.8:
        hour = rng.randint(h_start, h_end)
        minute = rng.randint(0, 59)
        second = rng.randint(0, 59)
        return base.replace(hour=hour, minute=minute, second=second)
    return base


def build_user_profiles() -> List[UserProfile]:
    return [
        UserProfile("alice", "US", (8, 17), 0.97, ["10.10.10.0/24", "192.168.10.0/24"]),
        UserProfile("bob", "US", (7, 16), 0.96, ["10.10.20.0/24", "192.168.20.0/24"]),
        UserProfile("carol", "CA", (9, 18), 0.98, ["10.10.30.0/24", "192.168.30.0/24"]),
        UserProfile("dave", "GB", (6, 15), 0.95, ["10.10.40.0/24", "192.168.40.0/24"]),
        UserProfile("svc_backup", "US", (0, 23), 0.995, ["10.99.0.0/24"]),  # service acct (always-on)
    ]


def generate_normal_events(
    rng: random.Random,
    users: List[UserProfile],
    start: datetime,
    end: datetime,
    n: int,
) -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []

    # Some common “reasons” and “auth types” to make logs feel realistic
    auth_types = [("password", 0.75), ("ssh_key", 0.18), ("mfa_push", 0.07)]
    event_sources = [("linux-sshd", 0.45), ("windows-ad", 0.35), ("vpn-gateway", 0.20)]
    user_agents = [
        ("OpenSSH_8.9", 0.35),
        ("Windows10", 0.30),
        ("macOS", 0.15),
        ("curl/7.81", 0.05),
        ("unknown", 0.15),
    ]

    for _ in range(n):
        u = rng.choice(users)
        ts = random_timestamp(rng, start, end, u.usual_hours if u.username != "svc_backup" else None)
        src = weighted_choice(rng, event_sources)
        auth = weighted_choice(rng, auth_types)
        ua = weighted_choice(rng, user_agents)

        source_ip = random_ip_from_cidr(rng, rng.choice(u.known_ip_blocks))

        country = u.home_country if rng.random() < 0.92 else rng.choice(["US", "CA", "GB", "DE", "FR", "AU", "JP"])
      
        success = rng.random() < u.success_rate
        result = "SUCCESS" if success else "FAILURE"

        results.append(
            {
                "timestamp_utc": ts.astimezone(timezone.utc).isoformat(timespec="seconds"),
                "username": u.username,
                "event_source": src,
                "auth_type": auth,
                "source_ip": source_ip,
                "country": country,
                "result": result,
                "failure_reason": "" if success else rng.choice(["bad_password", "mfa_denied", "user_not_found", "expired_password"]),
            }
        )

    return results


def inject_anomalies(
    rng: random.Random,
    events: List[Dict[str, str]],
    start: datetime,
    end: datetime,
) -> List[Dict[str, str]]:
    """Add a small number of clearly suspicious patterns."""
    anomalies: List[Dict[str, str]] = []

    # 1) Impossible travel: same user, close timestamps, far countries
    for user in ["alice", "bob"]:
        t1 = start + timedelta(hours=rng.randint(10, 40))
        t2 = t1 + timedelta(minutes=rng.randint(5, 35))
        anomalies.append(
            {
                "timestamp_utc": t1.astimezone(timezone.utc).isoformat(timespec="seconds"),
                "username": user,
                "event_source": "vpn-gateway",
                "auth_type": "password",
                "source_ip": random_ip_from_cidr(rng, "203.0.113.0/24"),
                "country": "US",
                "result": "SUCCESS",
                "failure_reason": "",
            }
        )
        anomalies.append(
            {
                "timestamp_utc": t2.astimezone(timezone.utc).isoformat(timespec="seconds"),
                "username": user,
                "event_source": "vpn-gateway",
                "auth_type": "password",
                "source_ip": random_ip_from_cidr(rng, "198.51.100.0/24"),
                "country": "JP",
                "result": "SUCCESS",
                "failure_reason": "",
            }
        )

    # 2) Brute-force then success
    victim = "carol"
    base = start + timedelta(hours=rng.randint(60, 90))
    brute_ip = random_ip_from_cidr(rng, "45.33.0.0/16")  # public-ish looking
    for i in range(12):
        anomalies.append(
            {
                "timestamp_utc": (base + timedelta(minutes=i)).astimezone(timezone.utc).isoformat(timespec="seconds"),
                "username": victim if rng.random() < 0.7 else rng.choice(["alice", "bob", "dave", "unknown_user"]),
                "event_source": "linux-sshd",
                "auth_type": "password",
                "source_ip": brute_ip,
                "country": rng.choice(["DE", "FR", "RU", "CN"]),
                "result": "FAILURE",
                "failure_reason": "bad_password",
            }
        )
    anomalies.append(
        {
            "timestamp_utc": (base + timedelta(minutes=13)).astimezone(timezone.utc).isoformat(timespec="seconds"),
            "username": victim,
            "event_source": "linux-sshd",
            "auth_type": "password",
            "source_ip": brute_ip,
            "country": rng.choice(["DE", "FR", "RU", "CN"]),
            "result": "SUCCESS",
            "failure_reason": "",
        }
    )

    # 3) Off-hours admin-ish behavior
    t = start + timedelta(days=2, hours=3, minutes=rng.randint(0, 59))
    anomalies.append(
        {
            "timestamp_utc": t.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "username": "dave",
            "event_source": "windows-ad",
            "auth_type": "mfa_push",
            "source_ip": random_ip_from_cidr(rng, "198.18.0.0/15"),
            "country": "AU",
            "result": "SUCCESS",
            "failure_reason": "",
        }
    )

    # 4) Service account from a new IP block (rare source)
    t = start + timedelta(days=1, hours=12, minutes=rng.randint(0, 59))
    anomalies.append(
        {
            "timestamp_utc": t.astimezone(timezone.utc).isoformat(timespec="seconds"),
            "username": "svc_backup",
            "event_source": "linux-sshd",
            "auth_type": "ssh_key",
            "source_ip": random_ip_from_cidr(rng, "172.31.0.0/16"),
            "country": "US",
            "result": "SUCCESS",
            "failure_reason": "",
        }
    )

    # Tag the injected anomalies
    for a in anomalies:
        a["is_injected_anomaly"] = "true"
    for e in events:
        e["is_injected_anomaly"] = "false"

    combined = events + anomalies
    rng.shuffle(combined)
    return combined


def write_csv(path: Path, rows: List[Dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "timestamp_utc",
        "username",
        "event_source",
        "auth_type",
        "source_ip",
        "country",
        "result",
        "failure_reason",
        "is_injected_anomaly",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            for k in fieldnames:
                r.setdefault(k, "")
            w.writerow({k: r.get(k, "") for k in fieldnames})


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate synthetic auth logs for Security AI Labs.")
    p.add_argument("--rows", type=int, default=1200, help="Number of normal log rows to generate (default: 1200)")
    p.add_argument("--days", type=int, default=7, help="Time window in days (default: 7)")
    p.add_argument("--seed", type=int, default=1337, help="RNG seed for reproducible output (default: 1337)")
    p.add_argument(
        "--out",
        type=str,
        default=str(Path("poc-auth-anomaly") / "data" / "sample_auth_logs.csv"),
        help="Output CSV path",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    rng = random.Random(args.seed)

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=args.days)

    users = build_user_profiles()
    normal = generate_normal_events(rng, users, start, end, args.rows)
    combined = inject_anomalies(rng, normal, start, end)

    out_path = Path(args.out)
    write_csv(out_path, combined)

    print(f"✅ Wrote {len(combined)} rows to: {out_path.as_posix()}")
    print("   (Includes injected anomalies tagged with is_injected_anomaly=true)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
