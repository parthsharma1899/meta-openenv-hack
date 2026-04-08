---
title: Cybersecurity Intrusion Detection Environment
emoji: "🛡"
colorFrom: red
colorTo: indigo
sdk: docker
pinned: false
---

# Cybersecurity Intrusion Detection Environment

An AI agent benchmark that simulates the workflow of a Security Operations Center (SOC) analyst — detecting threats in network traffic, constructing detection rules, and evaluating false-positive trade-offs.

> Network intrusion detection is a cornerstone of cybersecurity. This environment turns that process into a fully deterministic RL training benchmark.

---

## Overview

The agent receives hex-encoded network traffic containing known threat signatures. It must identify malicious patterns, design detection rules, and assess whether a rule is safe to deploy — mirroring exactly what SOC analysts do when triaging alerts.

Three tasks of increasing difficulty:

| Task | What the agent does | Max Score |
|------|---------------------|-----------|
| **Easy** | Find all XFF threat signatures in a 90-char hex traffic stream | 1.0 |
| **Medium** | Create a 20-char detection rule near a suspicious anomaly + score accuracy | 1.0 |
| **Hard** | Check false-positive rates for 3 candidate rules, rank them, pick the safest | 1.0 |

All scoring is **fully deterministic** — signatures are rule-based (XFF pattern), accuracy uses character-property formulas, false positives use sliding-window mismatch counting with core-region checks. No LLM-as-judge.

---

## Project Structure

```
ids_env/
├── __init__.py
├── models.py              # IDSAction, IDSObservation, IDSState (Pydantic)
├── client.py              # OpenEnv WebSocket client
├── openenv.yaml           # Submission manifest
├── pyproject.toml
├── requirements.txt
└── server/
    ├── environment.py     # All task logic + scoring functions
    ├── app.py             # FastAPI server
    └── Dockerfile
inference.py               # LLM agent script (OpenAI-compatible)
```

---

## Available Actions

```
scan_traffic(threat_positions)              -> submit found XFF signature positions
create_detection_rule(position)             -> get 20-char detection rule at a signature
evaluate_detection_accuracy(rule)           -> accuracy score [0-1]
evaluate_false_positives(rule_index)        -> false-positive count against baseline
select_optimal_rule(ranking, selected)      -> final safety ranking + recommendation
```

---

## Reward Structure

### Easy — Threat Signature Scanning
```
reward = correct_found / total_true_signatures   (recall, max 1.0)
```

### Medium — Detection Rule Design
```
reward = 0.4 (valid rule near anomaly) + 0.6 x accuracy_score
```

### Hard — Safety Assessment
```
reward = 0.3 (all 3 rules checked)
       + 0.4 (correct safety ranking)
       + 0.3 (correct rule selected)
```

---

## Running Locally

```bash
# Install dependencies
pip install openenv-core fastapi uvicorn pydantic

# Start the environment server
uvicorn ids_env.server.app:app --host 0.0.0.0 --port 8000 --reload

# Run the agent (in a separate terminal)
export HF_TOKEN=your_huggingface_token
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export IDS_TASK=easy          # easy | medium | hard
export IDS_ENV_URL=http://localhost:8000

python inference.py
```

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `HF_TOKEN` | Yes | Hugging Face API token |
| `API_BASE_URL` | Yes | LLM endpoint (default: HF Router) |
| `MODEL_NAME` | Yes | Model identifier |
| `IDS_TASK` | No | Task to run: `easy`, `medium`, `hard` (default: `easy`) |
| `IDS_ENV_URL` | No | Environment server URL (default: `http://localhost:8000`) |
| `IMAGE_NAME` | No | Docker image name (set by hackathon validator) |

---

## Docker

```bash
# Build
docker build -t ids-env -f ids_env/server/Dockerfile .

# Run
docker run -p 8000:8000 ids-env
```

---

## Cybersecurity Background

| Term | Meaning |
|------|---------|
| **XFF Signature** | Byte pattern (any hex char followed by FF) indicating malicious traffic |
| **Detection Rule** | 20-char hex substring used to flag future threats |
| **Detection Accuracy** | How reliably a rule identifies true threats (scored by character properties) |
| **False Positives** | Benign traffic incorrectly flagged as threats by a rule |
| **Baseline Traffic** | Known-clean traffic stream used to test for false positives |

---

## References

- [OpenEnv Framework](https://github.com/meta-pytorch/OpenEnv)

---

## Author

**Parth Sharma** — [github.com/parthsharma1899](https://github.com/parthsharma1899)
