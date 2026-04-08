"""
Cybersecurity Intrusion Detection Environment — Server Logic
=============================================================
Implements the three tasks described in the hackathon problem statement.
All scoring is fully deterministic — no LLM-as-judge needed.

IDS primer (brief)
-------------------
An Intrusion Detection System analyses network traffic to find:
  1. Known threat signatures — specific byte patterns (e.g., XFF) that
     indicate malicious activity.
  2. Detection rules — patterns extracted from traffic that can be used
     to flag future threats.
Finding threat signatures = finding all XFF motifs in the traffic stream.
"""

import random
import uuid
from typing import Any, Dict, List, Optional

from openenv.core.env_server import Environment

from ..models import IDSAction, IDSObservation, IDSState


# ============================================================================
# Synthetic network traffic data
# ============================================================================

HEX_CHARS = "0123456789ABCDEF"

# --- Easy task ---------------------------------------------------------------
# ~90-char hex traffic stream with several XFF threat signatures embedded at
# known positions.  The true signatures are computed at module load time by
# find_threat_signatures(), so they are always consistent with the algorithm.
EASY_TRAFFIC = (
    "A3C7BFFA0D1E2FFDE5B3C8AFFC0D1E3FF"
    "6A5B4C9DFFD0E2F4FF7B6A5D0EFFE1F3"
    "C8B7A6D2FF0E4F5C9BFFA7D3E6"
)

# --- Medium task -------------------------------------------------------------
# ~80-char hex traffic stream representing captured network data with a
# suspicious command byte (0xCC — software breakpoint / INT3, commonly found
# in shellcode) at a known position.  The closest upstream signature for a
# detection rule is within 22 bytes.
MEDIUM_TRAFFIC = (
    "E4A1B3C7D5F2E8A0B6C4D2FF"   # 26 chars (XFF signature at pos 22)
    "A1B3C5D7E9F0"               # 12 chars
    "CC"                          # suspicious byte at position 40
    "B3C7D5F2E8A0B6C4D2FFE4A1B3C7D5F2E8A0"  # 38 chars trailing
)
SUSPICIOUS_POSITION = 40   # anomalous command byte (INT3 / 0xCC)

# --- Hard task ---------------------------------------------------------------
# Three candidate detection rules with deliberately different false-positive
# profiles.  Rule 0 is DANGEROUS (many FPs), Rule 1 is SAFEST (fewest FPs),
# Rule 2 is MODERATE.
CANDIDATE_RULES = [
    "A3C7B9D1E5F2A0B6C4D2",   # Rule 0 – HIGH false positives
    "F1E2D3C4B5A69788F0E1",   # Rule 1 – SAFEST (true best)
    "A3C7B9D1E5F2A0B6C4E8",   # Rule 2 – MODERATE false positives
]

# 500-char baseline traffic excerpt with controlled false-positive sites.
# Constructed deterministically with random seed 42.
_BASELINE_SEED = 42


def _build_baseline_traffic() -> str:
    """
    Build a reproducible 500-char baseline (benign) traffic stream where:
      * Rule 0 has 6 false-positive sites (<=3 mismatches, core <=1 mismatch).
      * Rule 1 has 1 false-positive site (3 mismatches — borderline, core OK).
      * Rule 2 has 3 false-positive sites.
    """
    rng = random.Random(_BASELINE_SEED)
    traffic = list(rng.choices(HEX_CHARS, k=500))

    def embed(rule: str, positions: List[int], n_mismatches: int) -> None:
        for pos in positions:
            variant = list(rule)
            # Introduce n_mismatches at non-core positions (first 8 chars)
            mm_done = 0
            for idx in range(8):
                if mm_done >= n_mismatches:
                    break
                orig = variant[idx]
                replacement = rng.choice([c for c in HEX_CHARS if c != orig])
                variant[idx] = replacement
                mm_done += 1
            for k, ch in enumerate(variant):
                if pos + k < len(traffic):
                    traffic[pos + k] = ch

    # Rule 0 – 6 sites with 0-2 mismatches
    embed(CANDIDATE_RULES[0], [10, 55, 110, 170, 230, 300], 1)
    # One exact match for Rule 0 at position 10 (0 mismatches)
    for k, ch in enumerate(CANDIDATE_RULES[0]):
        traffic[10 + k] = ch

    # Rule 1 – 1 site with 3 mismatches (core region still OK)
    embed(CANDIDATE_RULES[1], [360], 3)

    # Rule 2 – 3 sites with 1-2 mismatches
    embed(CANDIDATE_RULES[2], [390, 430, 465], 1)

    return "".join(traffic[:500])


BASELINE_TRAFFIC = _build_baseline_traffic()


# ============================================================================
# IDS helper functions
# ============================================================================

def find_threat_signatures(traffic: str) -> List[int]:
    """
    Return positions of all XFF threat signatures in the traffic stream.

    Position i is a threat signature when traffic[i+1]=='F' and
    traffic[i+2]=='F' (i.e., the XFF triplet starts at i, where
    X = traffic[i] = any hex character).

    Also scans for 00X patterns (two leading null bytes — indicative of
    padding-based evasion) on the reverse representation.
    """
    t = traffic.upper()
    sites: List[int] = []

    # Forward: XFF
    for i in range(len(t) - 2):
        if t[i + 1] == "F" and t[i + 2] == "F":
            sites.append(i)

    # Reverse pattern: 00X (null-byte prefix, evasion indicator)
    for i in range(len(t) - 2):
        if t[i] == "0" and t[i + 1] == "0":
            sites.append(-(i + 2))   # negative index convention

    return sorted(set(sites))


def extract_detection_rule(traffic: str, sig_position: int) -> Optional[str]:
    """
    Extract the 20-char detection rule immediately upstream of the
    threat signature at sig_position.  Returns None if the position
    is out of range.
    """
    t = traffic.upper()
    start = sig_position - 20
    if start < 0 or sig_position + 2 >= len(t):
        return None
    return t[start:sig_position]


def compute_detection_accuracy(rule: str) -> float:
    """
    Deterministic detection accuracy score for a candidate rule.

    Factors considered:
      * Character diversity  (ideal: 40–70 % high-value hex chars 8–F)
      * Repeated-character stretches (>=4 identical → penalty)
      * Signature-region null-byte content (positions 15–19)
      * Terminal character preferences

    Returns a float in [0.0, 1.0].
    """
    if len(rule) != 20:
        return 0.0
    rule = rule.upper()
    if not all(c in HEX_CHARS for c in rule):
        return 0.0

    score = 0.5  # base

    # Character diversity — ratio of high-value hex chars (8-F)
    high = sum(1 for c in rule if c in "89ABCDEF") / 20.0
    if 0.40 <= high <= 0.70:
        score += 0.20
    elif high < 0.20 or high > 0.90:
        score -= 0.30
    else:
        score += 0.10 * (1 - abs(high - 0.55) / 0.35)

    # Repeated-character penalty
    for c in HEX_CHARS:
        if c * 4 in rule:
            score -= 0.15

    # Signature region (positions 15–19): penalise null bytes ('0')
    zeros_in_sig = rule[15:20].count("0")
    score -= zeros_in_sig * 0.02

    # Preferred terminal: 'F' at position 20 (index 19) — strong terminator
    if rule[19] == "F":
        score += 0.05

    # Leading byte: prefer 'A' or 'B' (common protocol headers)
    if rule[0] in "AB":
        score += 0.03

    return round(max(0.0, min(1.0, score)), 4)


def find_false_positives(
    rule: str,
    baseline: str,
    max_mismatches: int = 3,
    max_core_mismatches: int = 1,
) -> List[Dict[str, Any]]:
    """
    Slide a window of len(rule) across the baseline traffic and record
    every window where:
      * Total mismatches <= max_mismatches
      * Core-region mismatches (last 12 chars of rule) <= 1

    Returns a list of hit dicts: {position, mismatches, core_mismatches,
    sequence}.
    """
    rule = rule.upper()
    baseline = baseline.upper()
    n = len(rule)
    hits: List[Dict[str, Any]] = []

    for i in range(len(baseline) - n + 1):
        window = baseline[i : i + n]
        if not all(c in HEX_CHARS for c in window):
            continue
        total_mm = sum(1 for a, b in zip(rule, window) if a != b)
        core_mm = sum(
            1 for a, b in zip(rule[-12:], window[-12:]) if a != b
        )
        if total_mm <= max_mismatches and core_mm <= max_core_mismatches:
            hits.append(
                {
                    "position": i,
                    "mismatches": total_mm,
                    "core_mismatches": core_mm,
                    "sequence": window,
                }
            )

    return hits


# ============================================================================
# Pre-compute ground-truth values
# ============================================================================

_TRUE_THREAT_SIGS_EASY: List[int] = [
    s for s in find_threat_signatures(EASY_TRAFFIC) if s >= 0
]  # forward-pattern only for easy task

_TRUE_THREAT_SIGS_MEDIUM: List[int] = [
    s for s in find_threat_signatures(MEDIUM_TRAFFIC) if s >= 0
]

# Closest upstream threat signature to the suspicious position (must be
# <=22 chars upstream so a rule can span it)
_BEST_SIG_MEDIUM: int = max(
    (p for p in _TRUE_THREAT_SIGS_MEDIUM if 0 < SUSPICIOUS_POSITION - p <= 22),
    default=_TRUE_THREAT_SIGS_MEDIUM[0] if _TRUE_THREAT_SIGS_MEDIUM else 0,
)

_TRUE_FP_COUNTS: List[int] = [
    len(find_false_positives(r, BASELINE_TRAFFIC)) for r in CANDIDATE_RULES
]

_TRUE_BEST_RULE_INDEX: int = _TRUE_FP_COUNTS.index(
    min(_TRUE_FP_COUNTS)
)

# Safety ranking: sorted by false-positive count ascending (safest first)
_TRUE_SAFETY_RANKING: List[int] = sorted(
    range(3), key=lambda i: _TRUE_FP_COUNTS[i]
)


# ============================================================================
# Environment
# ============================================================================

class IDSEnvironment(Environment):
    """
    Cybersecurity Intrusion Detection Environment.

    Three tasks are supported (set IDS_TASK env var or pass task= to reset):
      easy   – Threat signature scanning
      medium – Detection rule creation + accuracy scoring
      hard   – False-positive safety assessment + rule recommendation
    """

    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self) -> None:
        self._state = IDSState()

    # ------------------------------------------------------------------ reset
    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        task: Optional[str] = None,
        **kwargs: Any,
    ) -> IDSObservation:
        import os

        task_name = (
            task
            or os.getenv("IDS_TASK", "easy")
        ).lower()
        if task_name not in ("easy", "medium", "hard"):
            task_name = "easy"

        eid = episode_id or str(uuid.uuid4())

        if task_name == "easy":
            self._state = IDSState(
                episode_id=eid,
                step_count=0,
                task_name="easy",
                traffic=EASY_TRAFFIC,
                true_threat_signatures=_TRUE_THREAT_SIGS_EASY,
            )
            return IDSObservation(
                done=False,
                reward=None,
                task="easy",
                traffic=EASY_TRAFFIC,
                message=(
                    "TASK (easy): Find all XFF threat signatures in the "
                    "network traffic stream below.\n"
                    "A threat signature is position i where traffic[i+1]=='F' "
                    "AND traffic[i+2]=='F' (X = any hex character).\n"
                    "Submit your answer with action_type='scan_traffic' and a "
                    "'threat_positions' list containing the 0-based index of "
                    "each X in the XFF triplet.\n\n"
                    f"Traffic stream ({len(EASY_TRAFFIC)} bytes):\n{EASY_TRAFFIC}"
                ),
            )

        elif task_name == "medium":
            self._state = IDSState(
                episode_id=eid,
                step_count=0,
                task_name="medium",
                traffic=MEDIUM_TRAFFIC,
                true_threat_signatures=_TRUE_THREAT_SIGS_MEDIUM,
                suspicious_position=SUSPICIOUS_POSITION,
                best_signature_position=_BEST_SIG_MEDIUM,
            )
            return IDSObservation(
                done=False,
                reward=None,
                task="medium",
                traffic=MEDIUM_TRAFFIC,
                suspicious_position=SUSPICIOUS_POSITION,
                anomaly_info=(
                    f"Suspicious command byte (0xCC / INT3) detected at "
                    f"position {SUSPICIOUS_POSITION}. "
                    "Create a detection rule to flag traffic near this anomaly."
                ),
                message=(
                    "TASK (medium): Create a 20-char detection rule targeting "
                    f"the suspicious activity at position {SUSPICIOUS_POSITION}.\n\n"
                    "Steps:\n"
                    "  1. Call action_type='create_detection_rule' with 'position' "
                    "     set to a valid XFF signature position upstream of the "
                    "     anomaly.\n"
                    "     The environment will return the 20-char detection rule.\n"
                    "  2. Call action_type='evaluate_detection_accuracy' with the "
                    "     returned 'rule' string to get the accuracy score.\n\n"
                    f"Traffic stream ({len(MEDIUM_TRAFFIC)} bytes):\n{MEDIUM_TRAFFIC}\n\n"
                    f"Anomaly info: suspicious byte (0xCC) at position "
                    f"{SUSPICIOUS_POSITION}."
                ),
            )

        else:  # hard
            self._state = IDSState(
                episode_id=eid,
                step_count=0,
                task_name="hard",
                traffic=MEDIUM_TRAFFIC,
                candidate_rules=CANDIDATE_RULES,
                baseline_traffic=BASELINE_TRAFFIC,
                true_false_positive_counts=_TRUE_FP_COUNTS,
                true_best_rule_index=_TRUE_BEST_RULE_INDEX,
                checked_rules={},
            )
            return IDSObservation(
                done=False,
                reward=None,
                task="hard",
                traffic=MEDIUM_TRAFFIC,
                candidate_rules=CANDIDATE_RULES,
                baseline_traffic=BASELINE_TRAFFIC,
                checked_so_far={},
                message=(
                    "TASK (hard): Evaluate false-positive rates for the 3 "
                    "candidate detection rules below against the provided "
                    "baseline traffic, then recommend the safest rule.\n\n"
                    "Steps:\n"
                    "  1. For each rule (index 0, 1, 2), call "
                    "     action_type='evaluate_false_positives' with "
                    "     'rule_index'.\n"
                    "  2. After checking all 3, call "
                    "     action_type='select_optimal_rule' "
                    "     with 'ranking' (list of indices, fewest FPs → most "
                    "     FPs) and 'selected_rule_index' (the safest rule).\n\n"
                    "Candidate rules:\n"
                    + "\n".join(
                        f"  [{i}] {r}" for i, r in enumerate(CANDIDATE_RULES)
                    )
                    + f"\n\nBaseline traffic ({len(BASELINE_TRAFFIC)} bytes) "
                    "provided in 'baseline_traffic' field."
                ),
            )

    # ------------------------------------------------------------------- step
    def step(
        self,
        action: IDSAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> IDSObservation:
        self._state.step_count += 1
        task = self._state.task_name

        if task == "easy":
            return self._step_easy(action)
        elif task == "medium":
            return self._step_medium(action)
        else:
            return self._step_hard(action)

    # --------------------------------------------------------- easy task step
    def _step_easy(self, action: IDSAction) -> IDSObservation:
        if action.action_type != "scan_traffic":
            return IDSObservation(
                done=False,
                reward=0.0,
                task="easy",
                traffic=self._state.traffic,
                message=(
                    f"Invalid action '{action.action_type}' for easy task. "
                    "Use action_type='scan_traffic'."
                ),
            )

        predicted = set(action.threat_positions or [])
        true_set = set(self._state.true_threat_signatures)

        correct = predicted & true_set
        recall = len(correct) / len(true_set) if true_set else 1.0
        # Small penalty for false positives to discourage guessing everything
        fp_penalty = max(0.0, (len(predicted - true_set) / max(len(true_set), 1)) * 0.1)
        reward = round(max(0.0, recall - fp_penalty), 4)

        self._state.cumulative_reward += reward

        return IDSObservation(
            done=True,
            reward=reward,
            task="easy",
            traffic=self._state.traffic,
            message=(
                f"Found {len(correct)}/{len(true_set)} threat signatures correctly. "
                f"False positives: {len(predicted - true_set)}. "
                f"Reward: {reward:.4f}\n"
                f"True signatures: {sorted(true_set)}\n"
                f"Your answer:     {sorted(predicted)}"
            ),
        )

    # ------------------------------------------------------- medium task step
    def _step_medium(self, action: IDSAction) -> IDSObservation:
        atype = action.action_type

        # ---- create_detection_rule ----
        if atype == "create_detection_rule":
            pos = action.position
            if pos is None:
                return IDSObservation(
                    done=False, reward=0.0, task="medium",
                    traffic=self._state.traffic,
                    suspicious_position=self._state.suspicious_position,
                    message="create_detection_rule requires a 'position' integer.",
                )

            # Valid signature nearby?
            true_sigs = set(self._state.true_threat_signatures)
            dist = abs(self._state.suspicious_position - pos)
            valid_sig = pos in true_sigs
            near_anomaly = dist <= 25

            rule = extract_detection_rule(self._state.traffic, pos)
            reward = 0.0
            if valid_sig and near_anomaly and rule:
                reward = 0.4
                self._state.designed_rule = rule
                msg = (
                    f"Valid signature at position {pos} (distance {dist} bytes "
                    f"from anomaly). Extracted rule: {rule}\n"
                    f"Now call evaluate_detection_accuracy with this rule."
                )
            else:
                reasons = []
                if not valid_sig:
                    reasons.append(f"position {pos} is not a valid XFF signature")
                if not near_anomaly:
                    reasons.append(f"too far from anomaly (dist={dist}, max=25)")
                if not rule:
                    reasons.append("could not extract 20-char rule (too close to edge)")
                msg = "Invalid create_detection_rule: " + "; ".join(reasons) + "."

            self._state.cumulative_reward += reward
            done = False  # Still need to score
            return IDSObservation(
                done=done, reward=reward, task="medium",
                traffic=self._state.traffic,
                suspicious_position=self._state.suspicious_position,
                returned_rule=rule if (valid_sig and near_anomaly) else None,
                message=msg,
            )

        # ---- evaluate_detection_accuracy ----
        elif atype == "evaluate_detection_accuracy":
            rule_str = (action.rule or "").upper().strip()
            if not rule_str:
                return IDSObservation(
                    done=False, reward=0.0, task="medium",
                    traffic=self._state.traffic,
                    message="evaluate_detection_accuracy requires a 'rule' string.",
                )

            acc = compute_detection_accuracy(rule_str)
            reward = round(0.6 * acc, 4)
            self._state.detection_score = acc
            self._state.cumulative_reward += reward

            return IDSObservation(
                done=True, reward=reward, task="medium",
                traffic=self._state.traffic,
                suspicious_position=self._state.suspicious_position,
                returned_rule=rule_str,
                detection_accuracy=acc,
                message=(
                    f"Detection accuracy score: {acc:.4f}\n"
                    f"Step reward: {reward:.4f} (= 0.6 x {acc:.4f})\n"
                    f"Cumulative reward: {self._state.cumulative_reward:.4f}"
                ),
            )

        else:
            return IDSObservation(
                done=False, reward=0.0, task="medium",
                traffic=self._state.traffic,
                message=(
                    f"Invalid action '{atype}' for medium task. "
                    "Use 'create_detection_rule' then "
                    "'evaluate_detection_accuracy'."
                ),
            )

    # --------------------------------------------------------- hard task step
    def _step_hard(self, action: IDSAction) -> IDSObservation:
        atype = action.action_type

        # ---- evaluate_false_positives ----
        if atype == "evaluate_false_positives":
            idx = action.rule_index
            if idx is None or idx not in (0, 1, 2):
                return IDSObservation(
                    done=False, reward=0.0, task="hard",
                    traffic=self._state.traffic,
                    candidate_rules=self._state.candidate_rules,
                    baseline_traffic=self._state.baseline_traffic,
                    checked_so_far=dict(self._state.checked_rules),
                    message="evaluate_false_positives requires 'rule_index' in {0, 1, 2}.",
                )

            rule_str = self._state.candidate_rules[idx]
            hits = find_false_positives(rule_str, self._state.baseline_traffic)
            count = len(hits)

            # Store result; reward 0.1 for each rule checked (max 3 x 0.1 = 0.3)
            key = str(idx)
            first_time = key not in self._state.checked_rules
            self._state.checked_rules[key] = count
            reward = 0.1 if first_time else 0.0
            self._state.cumulative_reward += reward

            return IDSObservation(
                done=False, reward=reward, task="hard",
                traffic=self._state.traffic,
                candidate_rules=self._state.candidate_rules,
                baseline_traffic=self._state.baseline_traffic,
                false_positive_result={
                    "rule_index": idx,
                    "rule_string": rule_str,
                    "false_positive_count": count,
                    "hits": hits[:5],          # first 5 hits shown
                    "total_hits": count,
                },
                checked_so_far=dict(self._state.checked_rules),
                message=(
                    f"Rule [{idx}] ({rule_str}): {count} false positive(s) found.\n"
                    f"Rules evaluated so far: {list(self._state.checked_rules.keys())}\n"
                    + ("Evaluate the remaining rules, then call select_optimal_rule."
                       if len(self._state.checked_rules) < 3
                       else "All 3 rules evaluated. Now call select_optimal_rule.")
                ),
            )

        # ---- select_optimal_rule ----
        elif atype == "select_optimal_rule":
            checked = self._state.checked_rules
            all_checked = len(checked) == 3
            ranking = action.ranking or []
            sel_idx = action.selected_rule_index

            reward = 0.0

            # 0.3 for having evaluated all 3 rules
            if all_checked:
                reward += 0.3

            # 0.4 for correct safety ranking
            if ranking and list(ranking) == _TRUE_SAFETY_RANKING:
                reward += 0.4

            # 0.3 for selecting the correct safest rule
            if sel_idx == _TRUE_BEST_RULE_INDEX:
                reward += 0.3

            self._state.cumulative_reward += reward

            true_counts = self._state.true_false_positive_counts
            return IDSObservation(
                done=True, reward=reward, task="hard",
                traffic=self._state.traffic,
                candidate_rules=self._state.candidate_rules,
                checked_so_far=dict(checked),
                message=(
                    f"=== Hard Task Complete ===\n"
                    f"True false-positive counts: {true_counts}\n"
                    f"True safety ranking (safest->most FPs): {_TRUE_SAFETY_RANKING}\n"
                    f"True safest rule: [{_TRUE_BEST_RULE_INDEX}] "
                    f"{CANDIDATE_RULES[_TRUE_BEST_RULE_INDEX]}\n\n"
                    f"Your ranking:     {ranking}\n"
                    f"Your selection:   [{sel_idx}]\n\n"
                    f"Step reward breakdown:\n"
                    f"  All 3 evaluated: {'+0.3' if all_checked else '+0.0'}\n"
                    f"  Correct ranking: {'+0.4' if list(ranking)==_TRUE_SAFETY_RANKING else '+0.0'}\n"
                    f"  Correct pick:    {'+0.3' if sel_idx==_TRUE_BEST_RULE_INDEX else '+0.0'}\n"
                    f"  Step reward:     {reward:.2f}\n"
                    f"  Cumulative:      {self._state.cumulative_reward:.4f}"
                ),
            )

        else:
            return IDSObservation(
                done=False, reward=0.0, task="hard",
                traffic=self._state.traffic,
                candidate_rules=self._state.candidate_rules,
                baseline_traffic=self._state.baseline_traffic,
                checked_so_far=dict(self._state.checked_rules),
                message=(
                    f"Invalid action '{atype}' for hard task. "
                    "Use 'evaluate_false_positives' (x3) then "
                    "'select_optimal_rule'."
                ),
            )

    # ------------------------------------------------------------------ state
    @property
    def state(self) -> IDSState:
        return self._state
