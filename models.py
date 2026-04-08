"""
Cybersecurity Intrusion Detection Environment — Data Models
===========================================================
Pydantic models defining the action, observation, and state for the
three-task IDS environment.

Tasks
-----
easy   : Find all known threat signatures in a network traffic stream.
medium : Create a detection rule near suspicious activity and score
         its detection accuracy.
hard   : Evaluate false positives for 3 candidate detection rules and
         recommend the one with lowest false-positive rate.
"""

from typing import Any, Dict, List, Optional
from openenv.core.env_server import Action, Observation, State


# ---------------------------------------------------------------------------
# Action
# ---------------------------------------------------------------------------

class IDSAction(Action):
    """
    A single step taken by the agent in the IDS environment.

    action_type must be one of:
        scan_traffic                 – (easy)   Submit predicted threat-signature positions.
        create_detection_rule        – (medium) Request the 20-char rule at a signature position.
        evaluate_detection_accuracy  – (medium) Score a detection rule for accuracy.
        evaluate_false_positives     – (hard)   Check false positives for one candidate rule.
        select_optimal_rule          – (hard)   Submit final rule ranking + recommendation.
    """

    action_type: str

    # --- scan_traffic (easy) -----------------------------------------------
    # Agent submits the list of threat-signature positions it found.
    threat_positions: Optional[List[int]] = None

    # --- create_detection_rule (medium) ------------------------------------
    # Agent selects which signature position to target.
    position: Optional[int] = None

    # --- evaluate_detection_accuracy (medium) ------------------------------
    # Agent provides the detection rule string to evaluate.
    rule: Optional[str] = None

    # --- evaluate_false_positives (hard) -----------------------------------
    # Agent specifies which candidate rule (0, 1, or 2) to check.
    rule_index: Optional[int] = None

    # --- select_optimal_rule (hard) ----------------------------------------
    # Agent's safety ranking (fewest FPs → most FPs) and final pick.
    ranking: Optional[List[int]] = None          # e.g. [1, 2, 0]
    selected_rule_index: Optional[int] = None    # index of chosen rule


# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

class IDSObservation(Observation):
    """
    What the agent sees after each step.

    Common fields (all tasks)
    -------------------------
    task              : "easy" | "medium" | "hard"
    traffic           : The network traffic stream being analysed.
    message           : Human-readable feedback / instructions.

    Easy-task fields
    ----------------
    (No extra context needed — full traffic stream is the task.)

    Medium-task fields
    ------------------
    suspicious_position : Index of the suspicious activity in the stream.
    anomaly_info        : Text description of the anomaly.
    returned_rule       : 20-char detection rule returned by create_detection_rule().
    detection_accuracy  : Float [0,1] returned by evaluate_detection_accuracy().

    Hard-task fields
    ----------------
    candidate_rules      : List of 3 detection rule strings to evaluate.
    baseline_traffic     : 500-char normal traffic stream for FP testing.
    false_positive_result: FP data returned by evaluate_false_positives().
    checked_so_far       : Dict mapping rule index → false-positive count.
    """

    task: str
    traffic: str
    message: str

    # Medium
    suspicious_position: Optional[int] = None
    anomaly_info: Optional[str] = None
    returned_rule: Optional[str] = None
    detection_accuracy: Optional[float] = None

    # Hard
    candidate_rules: Optional[List[str]] = None
    baseline_traffic: Optional[str] = None
    false_positive_result: Optional[Dict[str, Any]] = None
    checked_so_far: Optional[Dict[str, int]] = None


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class IDSState(State):
    """
    Internal episode metadata (not exposed to the agent directly).
    """

    task_name: str = "easy"
    traffic: str = ""

    # Easy
    true_threat_signatures: List[int] = []

    # Medium
    suspicious_position: int = 0
    best_signature_position: int = 0
    designed_rule: Optional[str] = None
    detection_score: Optional[float] = None

    # Hard
    candidate_rules: List[str] = []
    baseline_traffic: str = ""
    true_false_positive_counts: List[int] = []   # [count_r0, count_r1, count_r2]
    true_best_rule_index: int = 0                # index of safest rule
    checked_rules: Dict[str, int] = {}           # rule_index_str → count discovered

    # Reward tracking
    cumulative_reward: float = 0.0
