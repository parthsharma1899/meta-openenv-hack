# Cybersecurity Intrusion Detection Environment

An OpenEnv AI agent benchmark simulating a Security Operations Center (SOC) analyst workflow: detecting threats in network traffic, constructing detection rules, and evaluating false-positive trade-offs.

## Architecture

```
├── ids_env/                    # Primary Python package (server-side)
│   ├── __init__.py             # Exports IDSAction, IDSObservation, IDSState, IDSEnv
│   ├── models.py               # Pydantic models: IDSAction, IDSObservation, IDSState
│   ├── client.py               # WebSocket/Docker client (IDSEnv extends EnvClient)
│   ├── server/
│   │   ├── __init__.py
│   │   ├── environment.py      # Core task logic, scoring, synthetic data (the heart of the project)
│   │   ├── app.py              # FastAPI entry point (create_fastapi_app)
│   │   └── Dockerfile          # Container config (port 8000)
│   ├── openenv.yaml            # Task manifest (name, task list, max_steps)
│   ├── pyproject.toml          # Package metadata
│   └── requirements.txt        # Runtime deps
│
├── models.py                   # Root-level copy (used by inference.py via absolute import)
├── client.py                   # Root-level copy (used by inference.py via absolute import)
├── __init__.py                 # Root package exports
├── server/                     # Root-level server copy
│   ├── __init__.py
│   ├── environment.py          # Same logic as ids_env/server/environment.py
│   └── app.py                  # FastAPI app with explicit Action/Observation class args
├── inference.py                # LLM agent runner (connects to env, runs episodes)
├── openenv.yaml                # Root task manifest
├── pyproject.toml              # Root build config
├── requirements.txt            # Root deps
└── README.md                   # Project overview
```

**Dual structure**: Root-level files and `ids_env/` package contain equivalent code. Root files use absolute imports (`from models import ...`), package files use relative imports (`from .models import ...`). **Both must be kept in sync when making changes.** The root `server/app.py` differs slightly — it passes `IDSAction` and `IDSObservation` explicitly to `create_fastapi_app()` and includes a `main()` entry point.

## Domain & Data Format

All data is **hex-encoded network traffic** — strings of uppercase characters `0-9, A-F`.

| Concept | Implementation |
|---------|---------------|
| Network packet stream | Hex string (~90-500 chars) |
| Threat signature (XFF) | Position `i` where `traffic[i+1]=='F' and traffic[i+2]=='F'` |
| Reverse pattern (00X) | Position `i` where `traffic[i]=='0' and traffic[i+1]=='0'` (negative index) |
| Detection rule | 20-char hex substring extracted upstream of a signature position |
| Detection accuracy | Deterministic score based on rule character properties [0.0, 1.0] |
| False positives | Sliding-window mismatch count against baseline traffic |

### Synthetic Data (hardcoded in environment.py)

| Constant | Length | Purpose |
|----------|--------|---------|
| `EASY_TRAFFIC` | ~90 chars | Traffic stream with multiple XFF signatures for easy task |
| `MEDIUM_TRAFFIC` | ~80 chars | Traffic with suspicious byte (0xCC) at `SUSPICIOUS_POSITION` |
| `SUSPICIOUS_POSITION` | int | Index of anomalous activity in medium traffic |
| `CANDIDATE_RULES` | 3 x 20 chars | Three detection rules with different FP profiles |
| `BASELINE_TRAFFIC` | 500 chars | Benign traffic for FP testing (built deterministically, seed=42) |

The baseline traffic embeds controlled false-positive sites:
- Rule 0: 6 near-matches (HIGH risk — dangerous rule)
- Rule 1: 1 near-match (LOWEST risk — safest rule, the correct answer)
- Rule 2: 3 near-matches (MODERATE risk)

## Three Tasks

### Easy — Threat Detection (max score 1.0, max_steps 1)

The agent receives a hex traffic stream and must identify all XFF threat signature positions.

- **Action**: `scan_traffic` with `threat_positions: List[int]`
- **Reward formula**:
  ```
  recall = correctly_detected / total_true_signatures
  fp_penalty = (false_positives / total_true_signatures) * 0.1
  reward = max(0.0, recall - fp_penalty)
  ```

### Medium — Rule Generation (max score 1.0, max_steps 3)

The agent receives traffic with a suspicious anomaly and must create a detection rule near it.

- **Step 1**: `create_detection_rule` with `position: int`
  - Position must be a valid XFF signature AND within 25 bytes of the anomaly
  - Environment extracts the 20-char rule upstream of that position and returns it
  - **Reward**: 0.4 if valid position chosen
- **Step 2**: `evaluate_detection_accuracy` with `rule: str` (the 20-char rule)
  - **Reward**: 0.6 x accuracy_score

### Hard — Safety Evaluation (max score 1.0, max_steps 5)

The agent receives 3 candidate detection rules and baseline (benign) traffic. Must evaluate each rule's false-positive rate, rank them, and select the safest.

- **Steps 1-3**: `evaluate_false_positives` with `rule_index: int` (0, 1, or 2)
  - Returns false-positive count and sample hits for that rule
  - **Reward**: 0.1 per rule evaluated (first time only), max 0.3
- **Step 4**: `select_optimal_rule` with:
  - `ranking: List[int]` — indices ordered safest (fewest FPs) to most dangerous
  - `selected_rule_index: int` — the rule to deploy
  - **Reward breakdown**:
    - +0.3 if all 3 rules were evaluated
    - +0.4 if ranking exactly matches true safety order
    - +0.3 if selected rule is the true safest

## Action Space Reference

| Action | Task | Required Fields |
|--------|------|----------------|
| `scan_traffic` | easy | `threat_positions: List[int]` |
| `create_detection_rule` | medium | `position: int` |
| `evaluate_detection_accuracy` | medium | `rule: str` (20-char hex string) |
| `evaluate_false_positives` | hard | `rule_index: int` (0, 1, or 2) |
| `select_optimal_rule` | hard | `ranking: List[int]`, `selected_rule_index: int` |

## Data Models (models.py)

### IDSAction fields
- `action_type: str` — one of the 5 actions above
- `threat_positions: Optional[List[int]]` — for scan_traffic
- `position: Optional[int]` — for create_detection_rule
- `rule: Optional[str]` — for evaluate_detection_accuracy
- `rule_index: Optional[int]` — for evaluate_false_positives
- `ranking: Optional[List[int]]` — for select_optimal_rule
- `selected_rule_index: Optional[int]` — for select_optimal_rule

### IDSObservation fields
- `task, traffic, message` — common to all tasks
- `suspicious_position, anomaly_info, returned_rule, detection_accuracy` — medium task
- `candidate_rules, baseline_traffic, false_positive_result, checked_so_far` — hard task

### IDSState fields (internal, not exposed to agent)
- Tracks ground truth, cumulative reward, which rules have been checked, etc.

## Scoring Functions Detail (environment.py)

### find_threat_signatures(traffic)
Scans for XFF (forward, positive indices) and 00X (reverse, negative indices). Easy/medium tasks filter to forward-only (positive indices).

### extract_detection_rule(traffic, sig_position)
Returns `traffic[sig_position - 20 : sig_position]` or None if out of bounds.

### compute_detection_accuracy(rule)
Deterministic score for a 20-char hex rule. Returns float in [0.0, 1.0].

| Factor | Scoring |
|--------|---------|
| Base score | 0.5 |
| High-value hex chars (8-F) ratio 40-70% | +0.20 |
| High-value ratio < 20% or > 90% | -0.30 |
| High-value ratio other ranges | +0.10 scaled |
| 4+ consecutive identical chars | -0.15 per occurrence |
| '0' chars in positions 15-19 | -0.02 per zero |
| 'F' at position 19 | +0.05 |
| 'A' or 'B' at position 0 | +0.03 |

### find_false_positives(rule, baseline, max_mismatches=3, max_core_mismatches=1)
Slides a 20-char window across baseline traffic. A window is a false positive if:
- Total character mismatches <= 3
- Core region mismatches (last 12 chars) <= 1

Returns list of `{position, mismatches, core_mismatches, sequence}`.

### Pre-computed Ground Truth
Computed at module load time — always consistent with the algorithms:
- `_TRUE_THREAT_SIGS_EASY` / `_TRUE_THREAT_SIGS_MEDIUM` — forward-only signature positions
- `_BEST_SIG_MEDIUM` — closest upstream signature to the anomaly (within 22 chars)
- `_TRUE_FP_COUNTS` — false-positive counts per candidate rule
- `_TRUE_BEST_RULE_INDEX` — index of rule with fewest FPs
- `_TRUE_SAFETY_RANKING` — indices sorted by FP count ascending

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `IDS_TASK` | Task difficulty (easy/medium/hard) | `easy` |
| `IDS_ENV_URL` | Server URL for dev/fallback | HF Space URL |
| `IMAGE_NAME` | Docker image name (set by hackathon validator) | — |
| `API_BASE_URL` | LLM endpoint | `https://router.huggingface.co/v1` |
| `MODEL_NAME` | LLM model ID | `Qwen/Qwen2.5-72B-Instruct` |
| `HF_TOKEN` / `API_KEY` | API authentication key | — |

## Running Locally

**Server** (either method):
```bash
# Via ids_env package
uvicorn ids_env.server.app:app --host 0.0.0.0 --port 8000 --reload

# Via root server
python -m uvicorn server.app:app --host 0.0.0.0 --port 7860
```

**Inference** (requires running server or Docker image):
```bash
IDS_TASK=easy IDS_ENV_URL=http://localhost:8000 HF_TOKEN=your_token python inference.py
```

**Docker**:
```bash
docker build -t ids-env -f ids_env/server/Dockerfile .
docker run -p 8000:8000 ids-env
```

## Inference Script Output Format

The hackathon validator expects this exact stdout format:
```
[START] task=<t> env=<e> model=<m>
[STEP]  step=<n> action=<json> reward=<0.00> done=<true|false> error=<msg|null>
[END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...>
```

- `[END]` must ALWAYS be emitted, even on crash
- Success threshold: score >= 0.5
- Final score: `min(max(sum(step_rewards), 0.0), 1.0)`

## OpenEnv Framework Integration

This project uses the `openenv-core` library:
- **Server**: `IDSEnvironment` extends `openenv.core.env_server.Environment` (implements `reset()` and `step()`)
- **Client**: `IDSEnv` extends `openenv.core.env_client.EnvClient` (handles WebSocket/Docker communication)
- **App**: `create_fastapi_app(IDSEnvironment)` creates the FastAPI server automatically
- **Models**: `IDSAction` extends `Action`, `IDSObservation` extends `Observation`, `IDSState` extends `State`

## Key Constraints

- Reward formulas are fixed — do not change the scoring splits (0.4/0.6 for medium, 0.3/0.4/0.3 for hard)
- All data is hardcoded and deterministic — no randomness in task execution
- `_build_baseline_traffic()` uses seed=42 for reproducibility — changing this breaks ground truth
- Inference script must emit `[START]`, `[STEP]`, `[END]` log lines for the hackathon validator
- Final score is `min(max(sum(rewards), 0.0), 1.0)` — clamped to [0, 1]
- MAX_STEPS in inference.py is 6 (soft limit); per-task limits are in openenv.yaml
- Dependencies: openenv-core, fastapi, uvicorn, pydantic (no heavy ML libs needed)
- When modifying any source file, update BOTH the `ids_env/` package copy AND the root-level copy
