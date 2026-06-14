"""
BugLens — LLM-Based Bug Detection Tool
========================================
Author      : Aashik Poudel
Institution : LUT University, 2026
Thesis      : Automated Testing: Bug Identification Using Large Language Models

Pipeline:
  1. Code Embedding        (OpenAI text-embedding-3-small)
  2. CWE Vector Retrieval  (NumPy cosine similarity against CWE Top 25)
  3. Few-Shot Prompt Build (inject top-k CWE examples)
  4. LLM Analysis × N     (GPT-4o-mini, N=5 runs)
  5. Self-Consistency Vote (keep bugs appearing in k≥3 runs)
  6. Severity Scoring      (High×3 + Medium×2 + Low×1)
  7. Final Bug Report

References:
  - Wang et al. (2022) Self-Consistency Improves Chain of Thought Reasoning. NeurIPS.
  - Lewis et al. (2020) Retrieval-Augmented Generation for NLP Tasks. NeurIPS.
  - MITRE CWE Top 25 Most Dangerous Software Weaknesses.
  - Wei et al. (2022) Chain-of-Thought Prompting Elicits Reasoning in LLMs.
"""

from flask import Flask, request, jsonify, render_template
import requests
import json
import os
import time
import logging
import numpy as np
from cwe_knowledge_base import CWE_KNOWLEDGE_BASE

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────
OPENAI_API_KEY  = os.environ.get("OPENAI_API_KEY", "your-api-key-here")
ANALYSIS_MODEL  = "gpt-4o-mini"
EMBEDDING_MODEL = "text-embedding-3-small"
TEMPERATURE     = 0.7   # Higher temp for diversity across N runs
MAX_TOKENS      = 2000
MAX_CODE_CHARS  = 8000

# Self-Consistency parameters
N_RUNS          = 5     # Number of LLM calls per analysis
K_THRESHOLD     = 3     # Minimum runs a bug must appear in to be kept

# RAG parameters
TOP_K_CWE       = 3     # Number of CWE entries to retrieve per analysis


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 1 — EMBEDDING
#  Converts text to a vector using OpenAI text-embedding-3-small
# ═════════════════════════════════════════════════════════════════════════════

def get_embedding(text: str) -> np.ndarray:
    """
    Calls OpenAI Embeddings API to convert text into a dense vector.
    Used for both code input and CWE knowledge base entries.
    Model: text-embedding-3-small (1536 dimensions)
    """
    headers = {
        "Content-Type" : "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    payload = {
        "model": EMBEDDING_MODEL,
        "input": text[:8000]
    }
    response = requests.post(
        "https://api.openai.com/v1/embeddings",
        headers=headers,
        json=payload,
        timeout=30
    )
    if response.status_code != 200:
        raise Exception(f"Embedding API error: {response.text}")

    return np.array(response.json()["data"][0]["embedding"])


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """
    Computes cosine similarity between two embedding vectors.
    similarity = (a · b) / (||a|| × ||b||)
    Range: -1 (opposite) to 1 (identical)
    """
    return float(np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b) + 1e-10))


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 2 — CWE VECTOR RETRIEVAL
#  Embeds CWE knowledge base once at startup, retrieves top-k at inference
# ═════════════════════════════════════════════════════════════════════════════

def build_cwe_index() -> list:
    """
    Pre-computes embeddings for all CWE entries at startup.
    Each CWE is embedded as: name + description + example text.
    Stored in memory as a list of (cwe_entry, embedding_vector).
    """
    logger.info("Building CWE vector index...")
    index = []
    for cwe in CWE_KNOWLEDGE_BASE:
        text = f"{cwe['cwe_id']} {cwe['name']}: {cwe['description']} Example: {cwe['example']}"
        try:
            embedding = get_embedding(text)
            index.append((cwe, embedding))
            logger.info(f"  Embedded {cwe['cwe_id']}")
        except Exception as e:
            logger.warning(f"  Failed to embed {cwe['cwe_id']}: {e}")
    logger.info(f"CWE index built: {len(index)} entries")
    return index


def retrieve_top_k_cwes(code_embedding: np.ndarray, k: int = TOP_K_CWE) -> list:
    """
    Retrieves the top-k most semantically similar CWE entries for the input code.
    Uses cosine similarity between code embedding and pre-computed CWE embeddings.
    Returns list of CWE entries sorted by similarity (highest first).
    """
    scored = []
    for cwe_entry, cwe_embedding in CWE_INDEX:
        sim = cosine_similarity(code_embedding, cwe_embedding)
        scored.append((sim, cwe_entry))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [entry for _, entry in scored[:k]]


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 3 — FEW-SHOT PROMPT CONSTRUCTION
#  Injects retrieved CWE examples into the prompt (RAG pattern)
# ═════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are an expert software security engineer specialising in code review and vulnerability detection.
Your role is to systematically analyse source code and identify all bugs, vulnerabilities, and code quality issues.

Severity Classification:
- High   : Security vulnerabilities, crashes, data loss, or critical incorrect behaviour
- Medium : Resource leaks, poor error handling, logic issues under certain conditions
- Low    : Code quality issues, best practice violations, minor inefficiencies

Always respond with ONLY a valid JSON array. No text outside the JSON."""


def build_rag_prompt(code: str, language: str, retrieved_cwes: list) -> str:
    """
    Constructs a retrieval-augmented prompt that:
    1. Provides the LLM with relevant CWE vulnerability examples (few-shot)
    2. Asks the LLM to analyse the submitted code using those examples as reference
    3. Enforces a structured JSON output schema

    This grounds the LLM's analysis in standardised CWE taxonomy rather than
    relying solely on training memory. (Lewis et al., 2020 — RAG pattern)
    """
    # Build few-shot CWE examples section
    cwe_section = "\n\nRelevant vulnerability patterns to watch for (from CWE Top 25):\n"
    for i, cwe in enumerate(retrieved_cwes, 1):
        cwe_section += f"""
Example {i} — {cwe['cwe_id']}: {cwe['name']}
  Description : {cwe['description']}
  Vulnerable  : {cwe['example']}
  Fix         : {cwe['fix']}
"""

    return f"""Analyse the following {language} code for bugs, security vulnerabilities, and issues.
Use the CWE vulnerability patterns below as reference examples.
{cwe_section}

Return a JSON array where each element has exactly these fields:
[
  {{
    "bug_id"      : <integer starting from 1>,
    "severity"    : "High" | "Medium" | "Low",
    "location"    : "<function name or line number>",
    "type"        : "<bug category, use CWE name if applicable>",
    "cwe_id"      : "<CWE ID if applicable, else null>",
    "description" : "<clear explanation of the bug and why it is a problem>",
    "fix"         : "<specific code-level fix suggestion>"
  }}
]

If no bugs are found, return exactly: []

Code to analyse ({language}):
```{language}
{code}
```"""


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 4 — LLM ANALYSIS (N RUNS)
#  Calls GPT-4o-mini N times for self-consistency aggregation
# ═════════════════════════════════════════════════════════════════════════════

def call_llm_once(prompt: str) -> list:
    """
    Single LLM call. Returns parsed list of bugs.
    Temperature=0.7 ensures diversity across runs for self-consistency.
    """
    headers = {
        "Content-Type" : "application/json",
        "Authorization": f"Bearer {OPENAI_API_KEY}"
    }
    payload = {
        "model"      : ANALYSIS_MODEL,
        "temperature": TEMPERATURE,
        "max_tokens" : MAX_TOKENS,
        "messages"   : [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": prompt}
        ]
    }
    response = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers=headers,
        json=payload,
        timeout=60
    )
    if response.status_code != 200:
        raise Exception(f"OpenAI API error {response.status_code}: {response.text}")

    raw = response.json()["choices"][0]["message"]["content"].strip()

    # Strip markdown fences if present
    if raw.startswith("```"):
        parts = raw.split("```")
        raw = parts[1] if len(parts) > 1 else raw
        if raw.startswith("json"):
            raw = raw[4:]
    raw = raw.strip()

    bugs = json.loads(raw)
    return bugs if isinstance(bugs, list) else []


def run_n_analyses(prompt: str, n: int = N_RUNS) -> list:
    """
    Runs the LLM analysis N times on the same prompt.
    Returns a flat list of all bugs from all runs,
    each tagged with which run it came from.
    """
    all_runs = []
    for i in range(n):
        try:
            bugs = call_llm_once(prompt)
            for bug in bugs:
                bug["_run"] = i
            all_runs.append(bugs)
            logger.info(f"  Run {i+1}/{n}: {len(bugs)} bugs found")
        except Exception as e:
            logger.warning(f"  Run {i+1}/{n} failed: {e}")
            all_runs.append([])
    return all_runs


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 5 — SELF-CONSISTENCY VOTING
#  Aggregates N runs, keeps only bugs appearing in k≥3 runs
#  Reference: Wang et al. (2022) — NeurIPS
# ═════════════════════════════════════════════════════════════════════════════

def normalise_bug_key(bug: dict) -> str:
    """
    Creates a normalised key for bug deduplication across runs.
    Two bugs are considered the same if they share the same
    (severity, location, type) — case-insensitive.
    """
    severity = bug.get("severity", "").strip().lower()
    location = bug.get("location", "").strip().lower()
    bug_type = bug.get("type", "").strip().lower()[:30]
    return f"{severity}|{location}|{bug_type}"


def self_consistency_vote(all_runs: list, k: int = K_THRESHOLD) -> list:
    """
    Implements self-consistency voting (Wang et al., 2022):
    1. Normalise each bug into a canonical key
    2. Count how many runs report each unique bug
    3. Keep bugs that appear in at least k runs (high confidence)
    4. Flag bugs appearing in fewer runs as low-confidence

    Returns: list of confirmed bugs with confidence scores attached
    """
    from collections import defaultdict

    bug_counts  = defaultdict(int)
    bug_samples = {}

    for run_bugs in all_runs:
        seen_in_run = set()
        for bug in run_bugs:
            key = normalise_bug_key(bug)
            if key not in seen_in_run:
                bug_counts[key] += 1
                bug_samples[key] = bug
                seen_in_run.add(key)

    confirmed    = []
    low_conf     = []
    total_runs   = len(all_runs)

    for key, count in bug_counts.items():
        bug = dict(bug_samples[key])
        bug["confidence"]      = round(count / total_runs, 2)
        bug["confirmed_runs"]  = count
        bug["total_runs"]      = total_runs
        bug.pop("_run", None)

        if count >= k:
            confirmed.append(bug)
        else:
            bug["low_confidence"] = True
            low_conf.append(bug)

    # Sort confirmed by severity then confidence
    severity_order = {"High": 0, "Medium": 1, "Low": 2}
    confirmed.sort(key=lambda b: (
        severity_order.get(b.get("severity","Low"), 3),
        -b["confidence"]
    ))

    # Re-number bug IDs
    for i, bug in enumerate(confirmed, 1):
        bug["bug_id"] = i

    logger.info(f"Voting: {len(confirmed)} confirmed, {len(low_conf)} low-confidence discarded")
    return confirmed, low_conf


# ═════════════════════════════════════════════════════════════════════════════
#  STAGE 6 — SEVERITY SCORING
# ═════════════════════════════════════════════════════════════════════════════

def compute_severity_summary(bugs: list) -> dict:
    """
    Computes weighted risk score:
        Risk Score = (High × 3) + (Medium × 2) + (Low × 1)
    Risk Level:
        0        → Clean
        1–3      → Low Risk
        4–9      → Medium Risk
        10+      → High Risk
    """
    high   = sum(1 for b in bugs if b.get("severity") == "High")
    medium = sum(1 for b in bugs if b.get("severity") == "Medium")
    low    = sum(1 for b in bugs if b.get("severity") == "Low")
    score  = (high * 3) + (medium * 2) + (low * 1)

    if   score == 0  : risk_level = "Clean"
    elif score <= 3  : risk_level = "Low Risk"
    elif score <= 9  : risk_level = "Medium Risk"
    else             : risk_level = "High Risk"

    return {
        "total"      : len(bugs),
        "high"       : high,
        "medium"     : medium,
        "low"        : low,
        "risk_score" : score,
        "risk_level" : risk_level
    }


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN PIPELINE
# ═════════════════════════════════════════════════════════════════════════════

def analyse_code(code: str, language: str) -> dict:
    """
    Full BugLens pipeline:
      Stage 1: Embed input code
      Stage 2: Retrieve top-k CWE entries via cosine similarity
      Stage 3: Build RAG prompt with CWE few-shot examples
      Stage 4: Run LLM N=5 times
      Stage 5: Self-consistency voting (keep bugs in k≥3 runs)
      Stage 6: Severity scoring and risk classification
    """
    start = time.time()

    # Stage 1 — Embed code
    logger.info("Stage 1: Embedding code...")
    if CWE_INDEX:
        code_embedding = get_embedding(code)
        # Stage 2 — Retrieve CWEs
        logger.info("Stage 2: Retrieving CWEs...")
        retrieved_cwes = retrieve_top_k_cwes(code_embedding)
        logger.info(f"  Retrieved: {[c['cwe_id'] for c in retrieved_cwes]}")
    else:
        retrieved_cwes = []

    # Stage 3 — Build prompt
    logger.info("Stage 3: Building RAG prompt...")
    prompt = build_rag_prompt(code, language, retrieved_cwes)

    # Stage 4 — N runs
    logger.info(f"Stage 4: Running {N_RUNS} LLM analyses...")
    all_runs = run_n_analyses(prompt, N_RUNS)

    # Stage 5 — Vote
    logger.info("Stage 5: Self-consistency voting...")
    confirmed_bugs, low_conf_bugs = self_consistency_vote(all_runs, K_THRESHOLD)

    # Stage 6 — Score
    summary = compute_severity_summary(confirmed_bugs)

    elapsed = round(time.time() - start, 2)
    logger.info(f"Pipeline complete in {elapsed}s — {summary['total']} confirmed bugs")

    return {
        "bugs"            : confirmed_bugs,
        "low_confidence"  : low_conf_bugs,
        "summary"         : summary,
        "retrieved_cwes"  : [c["cwe_id"] + " " + c["name"] for c in retrieved_cwes],
        "n_runs"          : N_RUNS,
        "k_threshold"     : K_THRESHOLD,
        "model"           : ANALYSIS_MODEL,
        "language"        : language,
        "elapsed_sec"     : elapsed
    }


# ═════════════════════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ═════════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    data     = request.get_json(silent=True) or {}
    code     = data.get("code", "").strip()
    language = data.get("language", "Python").strip()

    if not code:
        return jsonify({"error": "No code provided."}), 400
    if len(code) > MAX_CODE_CHARS:
        return jsonify({"error": f"Code exceeds {MAX_CODE_CHARS} character limit."}), 400
    if not OPENAI_API_KEY:
        return jsonify({"error": "API key not configured on server."}), 500

    try:
        result = analyse_code(code, language)
        return jsonify(result)
    except json.JSONDecodeError:
        return jsonify({"error": "LLM returned invalid JSON. Please try again."}), 500
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status"     : "ok",
        "model"      : ANALYSIS_MODEL,
        "cwe_entries": len(CWE_INDEX),
        "n_runs"     : N_RUNS,
        "k_threshold": K_THRESHOLD,
        "api_ready"  : bool(OPENAI_API_KEY)
    })


# ── Build CWE index at startup ────────────────────────────────────────────────
if OPENAI_API_KEY:
    try:
        CWE_INDEX = build_cwe_index()
    except Exception as e:
        logger.warning(f"CWE index build failed: {e}. RAG disabled.")
        CWE_INDEX = []
else:
    logger.warning("No API key — CWE index skipped.")
    CWE_INDEX = []


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)