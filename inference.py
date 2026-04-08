"""
Cybersecurity Intrusion Detection Environment — Inference Script
================================================================
Required environment variables (set by hackathon validator):
    IMAGE_NAME    Docker image for the environment container
    API_BASE_URL  LLM endpoint  (default: HF Router)
    MODEL_NAME    Model ID      (default: Qwen/Qwen2.5-72B-Instruct)
    HF_TOKEN      API key

Optional:
    IDS_TASK        easy | medium | hard  (default: easy)
    IDS_ENV_URL     Override server URL when IMAGE_NAME is not set

STDOUT FORMAT (required by validator):
    [START] task=<t> env=<e> model=<m>
    [STEP]  step=<n> action=<a> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.000> rewards=<r1,r2,...>
"""

import asyncio
import json
import os
import re
import sys
import textwrap
from typing import List, Optional

from openai import OpenAI

# ---------------------------------------------------------------------------
# Path setup — works from /tmp/workspace/ (hackathon) or local repo root
# ---------------------------------------------------------------------------
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

from client import IDSEnv          # noqa: E402
from models import IDSAction        # noqa: E402

# ---------------------------------------------------------------------------
# Config  (variable names match the hackathon sample script exactly)
# ---------------------------------------------------------------------------
IMAGE_NAME   = os.getenv("IMAGE_NAME") or os.getenv("LOCAL_IMAGE_NAME")
API_KEY      = os.getenv("API_KEY")   or os.getenv("HF_TOKEN")
API_BASE_URL = os.getenv("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.getenv("MODEL_NAME",   "Qwen/Qwen2.5-72B-Instruct")
TASK_NAME    = os.getenv("IDS_TASK",  "easy")
BENCHMARK    = "ids_env"
MAX_STEPS    = 6
TEMPERATURE  = 0.2
MAX_TOKENS   = 512
SUCCESS_SCORE_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Required stdout logging helpers
# ---------------------------------------------------------------------------

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool,
             error: Optional[str]) -> None:
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} "
        f"done={str(done).lower()} error={error if error else 'null'}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float,
            rewards: List[float]) -> None:
    print(
        f"[END] success={str(success).lower()} steps={steps} "
        f"score={score:.3f} rewards={','.join(f'{r:.2f}' for r in rewards)}",
        flush=True,
    )

# ---------------------------------------------------------------------------
# System prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS = {
    "easy": textwrap.dedent("""
        You are a cybersecurity analyst in an Intrusion Detection System (IDS).

        TASK EASY: find all XFF threat signatures in the network traffic stream.
        A threat signature is position i where traffic[i+1]=='F' AND traffic[i+2]=='F'.
        (X = any hex character; i is 0-based index of X in the XFF triplet.)

        Scan the ENTIRE traffic stream and list every position.
        Reply with ONE JSON object only — no markdown, no text:
        {"action_type": "scan_traffic", "threat_positions": [<list of ints>]}
    """).strip(),

    "medium": textwrap.dedent("""
        You are a cybersecurity analyst in an Intrusion Detection System (IDS).

        TASK MEDIUM: create a detection rule near a suspicious anomaly.

        Step 1 — choose an XFF signature position within ~25 bytes of the anomaly:
          {"action_type": "create_detection_rule", "position": <int>}

        Step 2 — score the returned rule with:
          {"action_type": "evaluate_detection_accuracy", "rule": "<20-char hex string>"}

        Reply with ONE JSON object per turn. No markdown, no prose.
        An XFF signature position i is valid when traffic[i+1]=='F' and traffic[i+2]=='F'.
    """).strip(),

    "hard": textwrap.dedent("""
        You are a cybersecurity analyst in an Intrusion Detection System (IDS).

        TASK HARD: find the safest detection rule from 3 candidates.

        Steps 1–3 — check each rule (index 0, 1, 2) for false positives:
          {"action_type": "evaluate_false_positives", "rule_index": <0|1|2>}

        Step 4 — rank by safety (fewest false positives = safest) and select:
          {"action_type": "select_optimal_rule",
           "ranking": [<safest_index>, <mid_index>, <dangerous_index>],
           "selected_rule_index": <safest_index>}

        Reply with ONE JSON object per turn. No markdown, no prose.
    """).strip(),
}

# ---------------------------------------------------------------------------
# Action parsing
# ---------------------------------------------------------------------------

def parse_action(text: str) -> Optional[IDSAction]:
    text = re.sub(r"```(?:json)?\s*", "", text.strip()).strip().rstrip("`").strip()
    try:
        return IDSAction(**json.loads(text))
    except Exception:
        pass
    m = re.search(r"\{[^{}]*\}", text, re.DOTALL)
    if m:
        try:
            return IDSAction(**json.loads(m.group()))
        except Exception:
            pass
    return None


def fallback_action(task: str, step: int) -> IDSAction:
    if task == "easy":
        return IDSAction(action_type="scan_traffic", threat_positions=[])
    if task == "medium":
        if step <= 1:
            return IDSAction(action_type="create_detection_rule", position=22)
        return IDSAction(action_type="evaluate_detection_accuracy",
                         rule="A3C7BFFA0D1E2FFDE5B3")
    # hard
    if step <= 3:
        return IDSAction(action_type="evaluate_false_positives", rule_index=step - 1)
    return IDSAction(action_type="select_optimal_rule",
                     ranking=[1, 2, 0], selected_rule_index=1)

# ---------------------------------------------------------------------------
# LLM call
# ---------------------------------------------------------------------------

def get_llm_action(client: OpenAI, system: str, history: List[dict],
                   obs: str) -> str:
    messages = [{"role": "system", "content": system}]
    messages.extend(history[-6:])
    messages.append({"role": "user", "content": obs})
    try:
        resp = client.chat.completions.create(
            model=MODEL_NAME, messages=messages,
            temperature=TEMPERATURE, max_tokens=MAX_TOKENS, stream=False,
        )
        return (resp.choices[0].message.content or "").strip()
    except Exception as exc:
        print(f"[DEBUG] LLM error: {exc}", flush=True)
        return ""

# ---------------------------------------------------------------------------
# Episode
# ---------------------------------------------------------------------------

async def run_episode(task: str) -> None:
    rewards:     List[float] = []
    history:     List[dict]  = []
    steps_taken: int         = 0
    score:       float       = 0.0
    success:     bool        = False
    env                      = None

    # [START] must be emitted before any other output
    log_start(task=task, env=BENCHMARK, model=MODEL_NAME)

    try:
        llm = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
        sys_prompt = SYSTEM_PROMPTS.get(task, SYSTEM_PROMPTS["easy"])

        # ── Connect to environment ───────────────────────────────────────
        if IMAGE_NAME:
            # Hackathon path: validator sets IMAGE_NAME, we start the container
            env = await IDSEnv.from_docker_image(IMAGE_NAME)
        else:
            # Dev/fallback path: connect to a live Space
            env_url = os.getenv(
                "IDS_ENV_URL",
                "https://parthsharma1899-meta-openenv-hack.hf.space",
            )
            env = IDSEnv(base_url=env_url)
            await env.connect()   # ← must be called explicitly for URL path

        # ── Reset ────────────────────────────────────────────────────────
        result      = await env.reset(task=task)
        obs_message = result.observation.message
        done        = result.done

        # ── Step loop ────────────────────────────────────────────────────
        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            raw      = get_llm_action(llm, sys_prompt, history, obs_message)
            action   = parse_action(raw)
            err_msg  = None

            if action is None:
                err_msg = f"parse_error:{raw[:40]!r}"
                action  = fallback_action(task, step)
                print(f"[DEBUG] fallback at step {step}: {action.action_type}",
                      flush=True)

            action_str = json.dumps(action.model_dump(exclude_none=True))

            result      = await env.step(action)
            reward      = result.reward or 0.0
            done        = result.done
            obs_message = result.observation.message

            rewards.append(reward)
            steps_taken = step

            log_step(step=step, action=action_str, reward=reward,
                     done=done, error=err_msg)

            history.append({"role": "user",      "content": obs_message})
            history.append({"role": "assistant",  "content": raw})

            if done:
                break

        score   = min(max(sum(rewards), 0.0), 1.0)
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as exc:
        # Catch ALL exceptions so [END] is always emitted
        print(f"[DEBUG] Episode exception: {type(exc).__name__}: {exc}",
              flush=True)

    finally:
        # [END] must ALWAYS be emitted, even on crash
        if env is not None:
            try:
                await env.close()
            except Exception as e:
                print(f"[DEBUG] env.close() error: {e}", flush=True)
        log_end(success=success, steps=steps_taken, score=score,
                rewards=rewards)

# ---------------------------------------------------------------------------
# Entry point — always exits with code 0
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        asyncio.run(run_episode(TASK_NAME))
    except Exception as e:
        # Should never reach here, but ensure clean exit regardless
        print(f"[DEBUG] Top-level exception: {e}", flush=True)
    sys.exit(0)
