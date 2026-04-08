"""
Cybersecurity Intrusion Detection Environment — Client
======================================================
WebSocket / HTTP client for interacting with the deployed environment.
"""

from typing import Any, Dict

from openenv.core.env_client import EnvClient
from openenv.core.client_types import StepResult

from models import IDSAction, IDSObservation, IDSState


class IDSEnv(EnvClient[IDSAction, IDSObservation, IDSState]):
    """
    Client for the Cybersecurity Intrusion Detection environment.

    Usage
    -----
    with IDSEnv(base_url="https://your-space.hf.space").sync() as env:
        obs = env.reset(task="easy")
        result = env.step(IDSAction(
            action_type="scan_traffic",
            threat_positions=[5, 13, 22, 30]
        ))
        print(result.observation.message)
    """

    def _step_payload(self, action: IDSAction) -> Dict[str, Any]:
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict[str, Any]) -> StepResult:
        obs_data = payload.get("observation", {})
        obs = IDSObservation(
            done=payload.get("done", False),
            reward=payload.get("reward"),
            task=obs_data.get("task", "easy"),
            traffic=obs_data.get("traffic", ""),
            message=obs_data.get("message", ""),
            suspicious_position=obs_data.get("suspicious_position"),
            anomaly_info=obs_data.get("anomaly_info"),
            returned_rule=obs_data.get("returned_rule"),
            detection_accuracy=obs_data.get("detection_accuracy"),
            candidate_rules=obs_data.get("candidate_rules"),
            baseline_traffic=obs_data.get("baseline_traffic"),
            false_positive_result=obs_data.get("false_positive_result"),
            checked_so_far=obs_data.get("checked_so_far"),
        )
        return StepResult(
            observation=obs,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict[str, Any]) -> IDSState:
        return IDSState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            task_name=payload.get("task_name", "easy"),
            traffic=payload.get("traffic", ""),
            true_threat_signatures=payload.get("true_threat_signatures", []),
            suspicious_position=payload.get("suspicious_position", 0),
            best_signature_position=payload.get("best_signature_position", 0),
            designed_rule=payload.get("designed_rule"),
            detection_score=payload.get("detection_score"),
            candidate_rules=payload.get("candidate_rules", []),
            baseline_traffic=payload.get("baseline_traffic", ""),
            true_false_positive_counts=payload.get("true_false_positive_counts", []),
            true_best_rule_index=payload.get("true_best_rule_index", 0),
            checked_rules=payload.get("checked_rules", {}),
            cumulative_reward=payload.get("cumulative_reward", 0.0),
        )
