#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
V2X Mobility/Channel Simulation for the PQ Anonymous Traceable Authentication Framework

This script is a companion simulation for the paper:
  A Post-Quantum Anonymous and Traceable Authentication Framework for Multi-Agent Vehicular Collaboration

It extends the cryptographic prototype with a lightweight V2X message-layer simulator:
  - one-dimensional highway mobility with multiple lanes;
  - RSU coverage regions;
  - V2V/V2I receiver selection by communication range;
  - probabilistic channel loss and delay;
  - per-receiver replay cache;
  - malicious-but-authenticated semantic events that require TA tracing;
  - tampering and replay adversarial tests under mobility;
  - density and channel-loss sweeps.

Scope:
  This is not a full PHY/MAC/network-stack simulator such as SUMO+Veins.
  It is designed to evaluate whether the proposed authentication layer remains practical
  under dynamic vehicular-agent communication workloads.

Usage examples:
  python3 v2x_pq_auth_mobility_sim.py --mode mobility \
      --pq-module ./pq_agent_vanet_experiments_v2_kemdem.py \
      --agents 50 --duration 120 --msg-rate 0.05

  python3 v2x_pq_auth_mobility_sim.py --mode density \
      --pq-module ./pq_agent_vanet_experiments_v2_kemdem.py \
      --agent-list 10,30,50,100,200 --duration 120 --msg-rate 0.05

  python3 v2x_pq_auth_mobility_sim.py --mode channel \
      --pq-module ./pq_agent_vanet_experiments_v2_kemdem.py \
      --loss-list 0.0,0.05,0.1,0.2,0.3 --agents 50

  python3 v2x_pq_auth_mobility_sim.py --mode all \
      --pq-module ./pq_agent_vanet_experiments_v2_kemdem.py

Outputs are written to results_sim/ by default.
"""

from __future__ import annotations

import argparse
import csv
import heapq
import importlib.util
import math
import os
import sys
import random
import statistics
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_csv(path: str, rows: List[Dict[str, Any]]) -> None:
    if not rows:
        return
    ensure_dir(os.path.dirname(path) or ".")
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def mean(values: Sequence[float]) -> float:
    return statistics.mean(values) if values else 0.0


def p95(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    idx = int(math.ceil(0.95 * len(ordered))) - 1
    idx = max(0, min(idx, len(ordered) - 1))
    return ordered[idx]


def ring_distance(a: float, b: float, road_length: float) -> float:
    diff = abs(a - b)
    return min(diff, road_length - diff)


def parse_list_int(text: str) -> List[int]:
    return [int(x.strip()) for x in text.split(",") if x.strip()]


def parse_list_float(text: str) -> List[float]:
    return [float(x.strip()) for x in text.split(",") if x.strip()]


def import_pq_module(module_path: str):
    if not os.path.exists(module_path):
        raise FileNotFoundError(
            f"Cannot find PQ experiment module: {module_path}. "
            "Place this simulation script in the same directory as "
            "pq_agent_vanet_experiments_v2_kemdem.py or pass --pq-module."
        )
    spec = importlib.util.spec_from_file_location("pq_exp_v2", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module from {module_path}")

    # IMPORTANT: register the dynamically loaded module before executing it.
    # dataclasses inspect sys.modules[cls.__module__] while processing @dataclass.
    # If the module is not registered here, importing pq_agent_vanet_experiments_v2_kemdem.py
    # may fail at its @dataclass definitions on Python 3.11.
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def choose_default_mechanisms(pq: Any, sig_alg: Optional[str], kem_alg: Optional[str]) -> Tuple[str, str]:
    if sig_alg and kem_alg:
        return sig_alg, kem_alg
    enabled_sig = pq.oqs.get_enabled_sig_mechanisms()
    enabled_kem = pq.oqs.get_enabled_kem_mechanisms()
    chosen_sig = sig_alg or pq.choose_mechanism(pq.SIG_ALG_DEFAULT_CANDIDATES, enabled_sig, "signature")
    chosen_kem = kem_alg or pq.choose_mechanism(pq.KEM_ALG_DEFAULT_CANDIDATES, enabled_kem, "KEM")
    return chosen_sig, chosen_kem


# ---------------------------------------------------------------------------
# Mobility and channel model
# ---------------------------------------------------------------------------

@dataclass
class VehicleNode:
    idx: int
    position_m: float
    speed_mps: float
    lane: int
    agent: Any
    malicious: bool = False
    generated_messages: int = 0


@dataclass
class RsuNode:
    idx: int
    position_m: float


@dataclass(order=True)
class ScheduledDelivery:
    delivery_time: float
    receiver_id: str
    sender_id: int
    distance_m: float
    packet: Dict[str, Any]
    is_semantically_malicious: bool
    is_tampered: bool
    is_replay: bool
    generated_time: float


class HighwayV2XSimulation:
    def __init__(self, args: argparse.Namespace, pq: Any, sig_alg: str, kem_alg: str):
        self.args = args
        self.pq = pq
        self.sig_alg = sig_alg
        self.kem_alg = kem_alg
        self.rng = random.Random(args.seed)

        self.scheme = pq.ProposedFullScheme(
            sig_alg=sig_alg,
            kem_alg=kem_alg,
            payload_size=args.payload_size,
            context_binding=True,
            replay_protection=True,
        )
        self.scheme.setup()

        self.vehicles: List[VehicleNode] = []
        self.rsus: List[RsuNode] = []
        self.receiver_caches: Dict[str, Any] = {}
        self.event_queue: List[ScheduledDelivery] = []
        self.replay_pool: List[Tuple[Dict[str, Any], str, int, float]] = []

        # Metrics
        self.generated_messages = 0
        self.valid_messages = 0
        self.semantic_malicious_messages = 0
        self.tx_attempts = 0
        self.channel_drops = 0
        self.delivered = 0
        self.verified_ok = 0
        self.verify_failed = 0
        self.tamper_attacks = 0
        self.tamper_detected = 0
        self.replay_attacks = 0
        self.replay_detected = 0
        self.semantic_reports = 0
        self.trace_success = 0
        self.trace_failed = 0

        self.sign_times_ms: List[float] = []
        self.verify_times_ms: List[float] = []
        self.trace_times_ms: List[float] = []
        self.network_delays_ms: List[float] = []
        self.e2e_delays_ms: List[float] = []
        self.receiver_counts: List[int] = []
        self.json_sizes: List[int] = []
        self.binary_sizes: List[int] = []

    def initialize(self) -> None:
        self._init_rsus()
        self._init_vehicles_and_credentials()

    def _init_rsus(self) -> None:
        count = max(1, int(math.ceil(self.args.road_length / self.args.rsu_spacing)))
        self.rsus = [RsuNode(idx=i, position_m=(i * self.args.rsu_spacing) % self.args.road_length) for i in range(count)]
        for rsu in self.rsus:
            self.receiver_caches[f"RSU-{rsu.idx}"] = self.pq.ReplayCache()

    def _init_vehicles_and_credentials(self) -> None:
        malicious_count = int(round(self.args.agents * self.args.malicious_fraction))
        malicious_set = set(self.rng.sample(range(self.args.agents), malicious_count)) if malicious_count > 0 else set()

        for i in range(self.args.agents):
            pos = self.rng.uniform(0, self.args.road_length)
            speed = self.rng.uniform(self.args.min_speed, self.args.max_speed)
            lane = self.rng.randrange(max(1, self.args.lanes))
            agent = self.scheme.new_agent(i)
            # Credential issuing is done before the simulated communication starts.
            self.scheme.prepare_agent(agent, seq=0)
            node = VehicleNode(
                idx=i,
                position_m=pos,
                speed_mps=speed,
                lane=lane,
                agent=agent,
                malicious=(i in malicious_set),
            )
            self.vehicles.append(node)
            self.receiver_caches[f"VA-{i}"] = self.pq.ReplayCache()

    def update_mobility(self, dt: float) -> None:
        for v in self.vehicles:
            # Mild speed fluctuation to emulate traffic dynamics.
            v.speed_mps += self.rng.uniform(-self.args.accel_noise, self.args.accel_noise) * dt
            v.speed_mps = max(self.args.min_speed, min(self.args.max_speed, v.speed_mps))
            v.position_m = (v.position_m + v.speed_mps * dt) % self.args.road_length

    def get_receivers(self, sender: VehicleNode) -> List[Tuple[str, float]]:
        receivers: List[Tuple[str, float]] = []

        # V2V receivers within communication range.
        if self.args.enable_v2v:
            for other in self.vehicles:
                if other.idx == sender.idx:
                    continue
                d = ring_distance(sender.position_m, other.position_m, self.args.road_length)
                if d <= self.args.v2v_range:
                    receivers.append((f"VA-{other.idx}", d))

        # V2I receivers within RSU coverage.
        if self.args.enable_v2i:
            for rsu in self.rsus:
                d = ring_distance(sender.position_m, rsu.position_m, self.args.road_length)
                if d <= self.args.rsu_range:
                    receivers.append((f"RSU-{rsu.idx}", d))

        if self.args.max_receivers > 0 and len(receivers) > self.args.max_receivers:
            receivers = self.rng.sample(receivers, self.args.max_receivers)
        return receivers

    def channel_success_probability(self, distance_m: float) -> float:
        # A simple distance-sensitive packet delivery model.
        # base_loss controls environmental loss, while the exponential term models
        # decreasing link reliability near the edge of communication range.
        nominal_range = max(1.0, self.args.v2v_range)
        distance_factor = math.exp(-self.args.distance_loss_alpha * (distance_m / nominal_range) ** 2)
        p = (1.0 - self.args.base_loss) * distance_factor
        return max(0.0, min(1.0, p))

    def sample_delay_ms(self, distance_m: float) -> float:
        propagation_ms = distance_m / 3e8 * 1000.0
        jitter_ms = self.rng.expovariate(1.0 / max(0.001, self.args.delay_jitter_ms))
        return self.args.base_delay_ms + propagation_ms + jitter_ms

    def road_segment(self, position_m: float) -> str:
        return f"SEG-{int(position_m // self.args.segment_length)}"

    def group_id(self, position_m: float, sim_time: float) -> str:
        seg = int(position_m // self.args.segment_length)
        epoch = int(sim_time // max(1, self.args.group_epoch))
        return f"CAG-{seg}-{epoch}"

    def make_sim_message(self, sender: VehicleNode, seq: int, sim_time: float, semantic_malicious: bool) -> Dict[str, Any]:
        event_types = [
            "cooperative-perception",
            "emergency-warning",
            "lane-change-coordination",
            "federated-update-hash",
        ]
        event_type = self.rng.choice(event_types)
        content_payload = {
            "seq": seq,
            "sim_time": round(sim_time, 3),
            "position_m": round(sender.position_m, 2),
            "speed_mps": round(sender.speed_mps, 2),
            "lane": sender.lane,
            "payload": "X" * max(0, self.args.payload_size),
        }
        # The malicious flag is NOT included in the packet. It is only known by the simulator
        # and represents false semantic content that may be detected by an upper-layer detector.
        payload_hash = self.pq.sha256_hex(self.pq.canonical(content_payload))
        return {
            "version": self.pq.VERSION,
            "domain": self.pq.DOMAIN_MESSAGE,
            "msg_id": str(uuid.uuid4()),
            "timestamp": self.pq.now_ts(),
            "nonce": str(uuid.uuid4()),
            "agent_group_id": self.group_id(sender.position_m, sim_time),
            "road_segment": self.road_segment(sender.position_m),
            "event_type": event_type,
            "content": {
                "seq": seq,
                "sim_time": round(sim_time, 3),
                "payload_hash": payload_hash,
                "confidence": round(0.80 + self.rng.random() * 0.19, 4),
            },
        }

    def sign_custom_message(self, sender: VehicleNode, message: Dict[str, Any]) -> Dict[str, Any]:
        if sender.agent.credential is None:
            self.scheme.prepare_agent(sender.agent, seq=sender.generated_messages)
        t0 = time.perf_counter()
        packet = self.scheme._sign_packet_with_session(sender.agent, message, sender.agent.credential)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self.sign_times_ms.append(elapsed_ms)
        self.json_sizes.append(len(self.pq.canonical(packet)))
        self.binary_sizes.append(self.pq.compact_binary_size(packet))
        return packet

    def maybe_refresh_credential(self, sender: VehicleNode) -> None:
        if self.args.refresh_interval <= 0:
            return
        if sender.generated_messages > 0 and sender.generated_messages % self.args.refresh_interval == 0:
            self.scheme.prepare_agent(sender.agent, seq=sender.generated_messages)

    def tamper_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        tampered = self.pq.copy.deepcopy(packet)
        tampered["message"]["content"]["confidence"] = 0.001
        return tampered

    def schedule_packet(self, packet: Dict[str, Any], sender: VehicleNode, sim_time: float, is_semantic_malicious: bool, is_tampered: bool = False, is_replay: bool = False) -> None:
        receivers = self.get_receivers(sender)
        self.receiver_counts.append(len(receivers))
        for receiver_id, distance_m in receivers:
            self.tx_attempts += 1
            p_success = self.channel_success_probability(distance_m)
            if self.rng.random() > p_success:
                self.channel_drops += 1
                continue
            delay_ms = self.sample_delay_ms(distance_m)
            delivery = ScheduledDelivery(
                delivery_time=sim_time + delay_ms / 1000.0,
                receiver_id=receiver_id,
                sender_id=sender.idx,
                distance_m=distance_m,
                packet=packet,
                is_semantically_malicious=is_semantic_malicious,
                is_tampered=is_tampered,
                is_replay=is_replay,
                generated_time=sim_time,
            )
            heapq.heappush(self.event_queue, delivery)

    def generate_messages(self, sim_time: float) -> None:
        for sender in self.vehicles:
            if self.rng.random() > self.args.msg_rate * self.args.dt:
                continue

            self.maybe_refresh_credential(sender)
            semantic_malicious = sender.malicious and self.rng.random() < self.args.malicious_message_prob
            msg = self.make_sim_message(sender, self.generated_messages, sim_time, semantic_malicious)
            packet = self.sign_custom_message(sender, msg)
            sender.generated_messages += 1
            self.generated_messages += 1
            if semantic_malicious:
                self.semantic_malicious_messages += 1
            else:
                self.valid_messages += 1

            # Store a copy for replay attempts.
            self.replay_pool.append((packet, f"VA-{sender.idx}", sender.idx, sim_time))
            if len(self.replay_pool) > self.args.replay_pool_size:
                self.replay_pool.pop(0)

            # Tampering adversary modifies a packet after it is signed.
            if self.rng.random() < self.args.tamper_rate:
                self.tamper_attacks += 1
                packet_to_send = self.tamper_packet(packet)
                self.schedule_packet(packet_to_send, sender, sim_time, semantic_malicious, is_tampered=True)
            else:
                self.schedule_packet(packet, sender, sim_time, semantic_malicious)

        # Independent replay adversary resends old valid packets.
        if self.replay_pool and self.rng.random() < self.args.replay_rate * self.args.dt:
            old_packet, _, old_sender_idx, _ = self.rng.choice(self.replay_pool)
            sender = self.vehicles[old_sender_idx]
            self.replay_attacks += 1
            self.schedule_packet(old_packet, sender, sim_time, is_semantic_malicious=False, is_replay=True)

    def verify_at_receiver(self, receiver_id: str, packet: Dict[str, Any]) -> Tuple[bool, str, float]:
        old_cache = self.scheme.replay_cache
        self.scheme.replay_cache = self.receiver_caches.setdefault(receiver_id, self.pq.ReplayCache())
        try:
            t0 = time.perf_counter()
            ok, reason = self.scheme.verify_packet(packet)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            return ok, reason, elapsed_ms
        finally:
            self.scheme.replay_cache = old_cache

    def process_deliveries_until(self, sim_time: float) -> None:
        while self.event_queue and self.event_queue[0].delivery_time <= sim_time:
            delivery = heapq.heappop(self.event_queue)
            self.delivered += 1
            self.network_delays_ms.append((delivery.delivery_time - delivery.generated_time) * 1000.0)

            ok, reason, verify_ms = self.verify_at_receiver(delivery.receiver_id, delivery.packet)
            self.verify_times_ms.append(verify_ms)
            self.e2e_delays_ms.append((delivery.delivery_time - delivery.generated_time) * 1000.0 + verify_ms)

            if ok:
                self.verified_ok += 1
                # Semantic detector: cryptography cannot tell whether content is false.
                # If a valid but malicious event is detected by upper-layer logic, the TA traces it.
                if delivery.is_semantically_malicious and self.rng.random() < self.args.semantic_detect_rate:
                    self.semantic_reports += 1
                    t0 = time.perf_counter()
                    identity = self.scheme.trace_packet(delivery.packet)
                    trace_ms = (time.perf_counter() - t0) * 1000.0
                    self.trace_times_ms.append(trace_ms)
                    if identity is not None:
                        self.trace_success += 1
                    else:
                        self.trace_failed += 1
            else:
                self.verify_failed += 1
                if delivery.is_tampered:
                    self.tamper_detected += 1
                if delivery.is_replay:
                    self.replay_detected += 1

    def run(self) -> Dict[str, Any]:
        self.initialize()
        sim_time = 0.0
        steps = int(math.ceil(self.args.duration / self.args.dt))
        for _ in range(steps):
            self.update_mobility(self.args.dt)
            self.generate_messages(sim_time)
            self.process_deliveries_until(sim_time)
            sim_time += self.args.dt
        # Drain remaining deliveries.
        self.process_deliveries_until(sim_time + 10.0)
        return self.summary()

    def summary(self) -> Dict[str, Any]:
        channel_delivery_rate = self.delivered / self.tx_attempts if self.tx_attempts else 0.0
        verify_success_rate = self.verified_ok / self.delivered if self.delivered else 0.0
        tamper_detection_rate = self.tamper_detected / self.tamper_attacks if self.tamper_attacks else 0.0
        replay_detection_rate = self.replay_detected / self.replay_attacks if self.replay_attacks else 0.0
        trace_success_rate = self.trace_success / self.semantic_reports if self.semantic_reports else 0.0
        return {
            "agents": self.args.agents,
            "duration_s": self.args.duration,
            "msg_rate_hz_per_agent": self.args.msg_rate,
            "base_loss": self.args.base_loss,
            "v2v_range_m": self.args.v2v_range,
            "rsu_range_m": self.args.rsu_range,
            "rsu_count": len(self.rsus),
            "generated_messages": self.generated_messages,
            "semantic_malicious_messages": self.semantic_malicious_messages,
            "tx_attempts": self.tx_attempts,
            "delivered_packets": self.delivered,
            "channel_delivery_rate": round(channel_delivery_rate, 6),
            "verified_ok": self.verified_ok,
            "verify_failed": self.verify_failed,
            "verify_success_rate": round(verify_success_rate, 6),
            "tamper_attacks": self.tamper_attacks,
            "tamper_detected": self.tamper_detected,
            "tamper_detection_rate": round(tamper_detection_rate, 6),
            "replay_attacks": self.replay_attacks,
            "replay_detected": self.replay_detected,
            "replay_detection_rate": round(replay_detection_rate, 6),
            "semantic_reports": self.semantic_reports,
            "trace_success": self.trace_success,
            "trace_failed": self.trace_failed,
            "trace_success_rate": round(trace_success_rate, 6),
            "avg_receivers_per_message": round(mean(self.receiver_counts), 4),
            "sign_avg_ms": round(mean(self.sign_times_ms), 4),
            "verify_avg_ms": round(mean(self.verify_times_ms), 4),
            "verify_p95_ms": round(p95(self.verify_times_ms), 4),
            "trace_avg_ms": round(mean(self.trace_times_ms), 4),
            "trace_p95_ms": round(p95(self.trace_times_ms), 4),
            "network_delay_avg_ms": round(mean(self.network_delays_ms), 4),
            "network_delay_p95_ms": round(p95(self.network_delays_ms), 4),
            "e2e_delay_avg_ms": round(mean(self.e2e_delays_ms), 4),
            "e2e_delay_p95_ms": round(p95(self.e2e_delays_ms), 4),
            "json_size_avg_bytes": round(mean(self.json_sizes), 2),
            "binary_size_avg_bytes": round(mean(self.binary_sizes), 2),
            "auth_verifications_per_sec": round(self.delivered / self.args.duration if self.args.duration else 0.0, 4),
        }


# ---------------------------------------------------------------------------
# Experiment modes
# ---------------------------------------------------------------------------

def run_single(args: argparse.Namespace, pq: Any, sig_alg: str, kem_alg: str) -> Dict[str, Any]:
    sim = HighwayV2XSimulation(args, pq, sig_alg, kem_alg)
    summary = sim.run()
    print_summary("V2X Mobility Simulation", summary)
    ensure_dir(args.out_dir)
    write_csv(os.path.join(args.out_dir, "v2x_mobility_summary.csv"), [summary])
    return summary


def run_density(args: argparse.Namespace, pq: Any, sig_alg: str, kem_alg: str) -> List[Dict[str, Any]]:
    rows = []
    base_agents = args.agents
    for n in parse_list_int(args.agent_list):
        args.agents = n
        args.seed += 1
        print(f"\n[Density sweep] agents={n}")
        rows.append(HighwayV2XSimulation(args, pq, sig_alg, kem_alg).run())
    args.agents = base_agents
    write_csv(os.path.join(args.out_dir, "v2x_density_sweep.csv"), rows)
    print_table("V2X Density Sweep", rows)
    return rows


def run_channel(args: argparse.Namespace, pq: Any, sig_alg: str, kem_alg: str) -> List[Dict[str, Any]]:
    rows = []
    base_loss = args.base_loss
    for loss in parse_list_float(args.loss_list):
        args.base_loss = loss
        args.seed += 1
        print(f"\n[Channel sweep] base_loss={loss}")
        rows.append(HighwayV2XSimulation(args, pq, sig_alg, kem_alg).run())
    args.base_loss = base_loss
    write_csv(os.path.join(args.out_dir, "v2x_channel_sweep.csv"), rows)
    print_table("V2X Channel Sweep", rows)
    return rows


def run_all(args: argparse.Namespace, pq: Any, sig_alg: str, kem_alg: str) -> None:
    run_single(args, pq, sig_alg, kem_alg)
    run_density(args, pq, sig_alg, kem_alg)
    run_channel(args, pq, sig_alg, kem_alg)


def print_summary(title: str, row: Dict[str, Any]) -> None:
    print(f"\n=== {title} ===")
    for k, v in row.items():
        print(f"{k:32s}: {v}")


def print_table(title: str, rows: List[Dict[str, Any]]) -> None:
    print(f"\n=== {title} ===")
    if not rows:
        print("No rows.")
        return
    preferred_cols = [
        "agents", "base_loss", "generated_messages", "tx_attempts", "delivered_packets",
        "channel_delivery_rate", "verify_success_rate", "trace_success_rate",
        "sign_avg_ms", "verify_avg_ms", "e2e_delay_avg_ms", "auth_verifications_per_sec",
    ]
    cols = [c for c in preferred_cols if c in rows[0]]
    widths = {c: max(len(c), *(len(str(r.get(c, ""))) for r in rows)) for c in cols}
    header = " | ".join(c.ljust(widths[c]) for c in cols)
    sep = "-+-".join("-" * widths[c] for c in cols)
    print(header)
    print(sep)
    for r in rows:
        print(" | ".join(str(r.get(c, "")).ljust(widths[c]) for c in cols))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="V2X mobility/channel simulation for the PQ authentication framework")
    p.add_argument("--mode", choices=["mobility", "density", "channel", "all"], default="mobility")
    p.add_argument("--pq-module", default="pq_agent_vanet_experiments_v2_kemdem.py", help="Path to the PQ experiment module")
    p.add_argument("--out-dir", default="results_sim")
    p.add_argument("--sig-alg", default=None, help="Override signature algorithm, e.g., ML-DSA-65")
    p.add_argument("--kem-alg", default=None, help="Override KEM algorithm, e.g., ML-KEM-768")

    # Scenario and mobility parameters
    p.add_argument("--agents", type=int, default=50)
    p.add_argument("--agent-list", default="10,30,50,100,200")
    p.add_argument("--duration", type=float, default=120.0, help="Simulation duration in seconds")
    p.add_argument("--dt", type=float, default=1.0, help="Simulation time step in seconds")
    p.add_argument("--road-length", type=float, default=5000.0)
    p.add_argument("--lanes", type=int, default=3)
    p.add_argument("--min-speed", type=float, default=15.0)
    p.add_argument("--max-speed", type=float, default=33.0)
    p.add_argument("--accel-noise", type=float, default=0.8)
    p.add_argument("--segment-length", type=float, default=500.0)
    p.add_argument("--group-epoch", type=float, default=30.0)

    # Communication parameters
    p.add_argument("--enable-v2v", action="store_true", default=True)
    p.add_argument("--disable-v2v", dest="enable_v2v", action="store_false")
    p.add_argument("--enable-v2i", action="store_true", default=True)
    p.add_argument("--disable-v2i", dest="enable_v2i", action="store_false")
    p.add_argument("--v2v-range", type=float, default=300.0)
    p.add_argument("--rsu-range", type=float, default=600.0)
    p.add_argument("--rsu-spacing", type=float, default=1000.0)
    p.add_argument("--max-receivers", type=int, default=20, help="Limit receivers per message; 0 means no limit")
    p.add_argument("--base-loss", type=float, default=0.05)
    p.add_argument("--loss-list", default="0.0,0.05,0.1,0.2,0.3")
    p.add_argument("--distance-loss-alpha", type=float, default=0.7)
    p.add_argument("--base-delay-ms", type=float, default=3.0)
    p.add_argument("--delay-jitter-ms", type=float, default=2.0)

    # Workload and adversary parameters
    p.add_argument("--msg-rate", type=float, default=0.05, help="Per-agent message generation rate in Hz")
    p.add_argument("--payload-size", type=int, default=256)
    p.add_argument("--malicious-fraction", type=float, default=0.05)
    p.add_argument("--malicious-message-prob", type=float, default=0.5)
    p.add_argument("--semantic-detect-rate", type=float, default=0.9)
    p.add_argument("--tamper-rate", type=float, default=0.02)
    p.add_argument("--replay-rate", type=float, default=0.02, help="Replay attempts per second")
    p.add_argument("--replay-pool-size", type=int, default=100)
    p.add_argument("--refresh-interval", type=int, default=0, help="Refresh anonymous credential every N generated messages per agent; 0 disables refresh")
    p.add_argument("--seed", type=int, default=20260520)
    return p


def main() -> None:
    args = build_parser().parse_args()
    pq = import_pq_module(args.pq_module)
    sig_alg, kem_alg = choose_default_mechanisms(pq, args.sig_alg, args.kem_alg)
    print(f"Using signature algorithm: {sig_alg}")
    print(f"Using KEM algorithm      : {kem_alg}")
    print(f"Output directory         : {args.out_dir}")
    ensure_dir(args.out_dir)

    if args.mode == "mobility":
        run_single(args, pq, sig_alg, kem_alg)
    elif args.mode == "density":
        run_density(args, pq, sig_alg, kem_alg)
    elif args.mode == "channel":
        run_channel(args, pq, sig_alg, kem_alg)
    elif args.mode == "all":
        run_all(args, pq, sig_alg, kem_alg)
    else:  # pragma: no cover
        raise ValueError(args.mode)


if __name__ == "__main__":
    main()
