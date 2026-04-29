"""
Azure Content Safety SDK — Test Script
=======================================
Tests each prompt in inputs.txt against all four harm categories
(Hate, Sexual, Violence, SelfHarm) using multiple threshold combinations.

Requirements:
    pip install azure-ai-contentsafety azure-core

Usage:
    Set environment variables, then run:
        python test_content_safety.py
    or pass args directly:
        python test_content_safety.py --endpoint <URL> --key <KEY>
"""

import os
import sys
import csv
import json
import argparse
import itertools
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

# ── Load .env file ────────────────────────────────────────────────────────────
load_dotenv()

# ── Azure SDK imports ──────────────────────────────────────────────────────────
try:
    from azure.ai.contentsafety import ContentSafetyClient
    from azure.ai.contentsafety.models import (
        AnalyzeTextOptions,
        TextCategory,
    )
    from azure.core.credentials import AzureKeyCredential
    from azure.core.exceptions import HttpResponseError
except ImportError:
    print(
        "\n[ERROR] Azure Content Safety SDK not installed.\n"
        "Run:  pip install azure-ai-contentsafety azure-core\n"
    )
    sys.exit(1)


# ── Configuration ──────────────────────────────────────────────────────────────

INPUTS_FILE = Path(__file__).parent / "inputs.txt"

# Thresholds to test (Azure severity scores are 0-6 in increments of 2)
# A result is flagged when its severity >= threshold.
THRESHOLDS_TO_TEST = [0, 2, 4, 5, 6, 7]  # Added 7 to test above max severity

# All four harm categories
ALL_CATEGORIES = [
    TextCategory.HATE,
    TextCategory.SEXUAL,
    TextCategory.VIOLENCE,
    TextCategory.SELF_HARM,
]

CATEGORY_DISPLAY = {
    TextCategory.HATE: "Hate",
    TextCategory.SEXUAL: "Sexual",
    TextCategory.VIOLENCE: "Violence",
    TextCategory.SELF_HARM: "SelfHarm",
}


# ── Helpers ────────────────────────────────────────────────────────────────────

def load_prompts(path: Path) -> list[dict]:
    """Parse inputs.txt → list of {category, severity_label, prompt}."""
    prompts = []
    with open(path, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", maxsplit=2)
            if len(parts) != 3:
                print(f"[WARN] Skipping malformed line: {line!r}")
                continue
            prompts.append(
                {
                    "category": parts[0].strip(),
                    "severity_label": parts[1].strip(),
                    "prompt": parts[2].strip(),
                }
            )
    return prompts


def build_client(endpoint: str, key: str) -> ContentSafetyClient:
    return ContentSafetyClient(endpoint, AzureKeyCredential(key))


def analyze_text(client: ContentSafetyClient, text: str) -> dict:
    """
    Call the API and return raw severity scores for all four categories.
    Returns: {category_name: severity_score, ...}
    """
    request = AnalyzeTextOptions(text=text, categories=ALL_CATEGORIES)
    try:
        response = client.analyze_text(request)
    except HttpResponseError as e:
        print(f"  [API ERROR] {e.error.code}: {e.error.message}")
        return {}

    scores = {}
    for result in response.categories_analysis:
        scores[result.category] = result.severity  # 0, 2, 4, or 6
    return scores


def apply_threshold(scores: dict, threshold: int) -> dict:
    """
    Return a flag dict: category → True if severity >= threshold, else False.
    """
    return {cat: (scores.get(cat, 0) >= threshold) for cat in ALL_CATEGORIES}


def severity_label(score: int) -> str:
    mapping = {0: "Safe", 2: "Low", 4: "Medium", 6: "High"}
    return mapping.get(score, f"Unknown({score})")


# ── Pretty-print helpers ───────────────────────────────────────────────────────

SEP = "─" * 90
HEADER_SEP = "═" * 90


def print_header():
    print(f"\n{HEADER_SEP}")
    print(" Azure Content Safety SDK — Multi-Threshold Test Runner")
    print(f" Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(HEADER_SEP)


def print_prompt_block(idx: int, total: int, entry: dict):
    print(f"\n{SEP}")
    print(
        f" Prompt {idx}/{total} | Category: {entry['category'].upper()}"
        f" | Expected Severity: {entry['severity_label'].upper()}"
    )
    print(f" Text: {entry['prompt'][:120]}{'...' if len(entry['prompt']) > 120 else ''}")
    print(SEP)


def print_scores(scores: dict):
    print("\n  RAW API SCORES:")
    for cat in ALL_CATEGORIES:
        score = scores.get(cat, 0)
        bar = "█" * (score + 1) + "░" * (6 - score)
        print(
            f"    {CATEGORY_DISPLAY[cat]:<12} score={score}  [{bar}]  ({severity_label(score)})"
        )


def print_threshold_results(scores: dict, thresholds: list[int]):
    print("\n  THRESHOLD ANALYSIS:")
    print(f"  {'Threshold':<12}", end="")
    for cat in ALL_CATEGORIES:
        print(f"  {CATEGORY_DISPLAY[cat]:<14}", end="")
    print()
    print("  " + "─" * 72)

    for thresh in thresholds:
        flags = apply_threshold(scores, thresh)
        print(f"  {'≥ ' + str(thresh):<12}", end="")
        for cat in ALL_CATEGORIES:
            flag = flags[cat]
            icon = "🚫 FLAGGED " if flag else "✅ PASSED  "
            print(f"  {icon:<14}", end="")
        print()


# ── CSV / JSON export ──────────────────────────────────────────────────────────

def save_csv(results: list[dict], path: Path):
    fieldnames = [
        "prompt_idx", "category", "severity_label", "prompt",
        "hate_score", "sexual_score", "violence_score", "selfharm_score",
        "threshold", "hate_flagged", "sexual_flagged", "violence_flagged", "selfharm_flagged",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[EXPORT] CSV saved → {path}")


def save_json(results: list[dict], path: Path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"[EXPORT] JSON saved → {path}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Azure Content Safety test runner")
    parser.add_argument(
        "--endpoint",
        default=os.environ.get("AZURE_CONTENT_SAFETY_ENDPOINT", ""),
        help="Azure Content Safety endpoint URL",
    )
    parser.add_argument(
        "--key",
        default=os.environ.get("AZURE_CONTENT_SAFETY_KEY", ""),
        help="Azure Content Safety API key",
    )
    parser.add_argument(
        "--inputs",
        default=str(INPUTS_FILE),
        help="Path to inputs.txt (default: ./inputs.txt)",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=int,
        default=THRESHOLDS_TO_TEST,
        help="Threshold values to test (default: 0 2 4 6)",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save CSV/JSON results (default: current dir)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse inputs and print prompts without calling the API",
    )
    args = parser.parse_args()

    # ── Validate ──────────────────────────────────────────────────────────────
    if not args.dry_run:
        if not args.endpoint:
            print("[ERROR] Provide --endpoint or set AZURE_CONTENT_SAFETY_ENDPOINT")
            sys.exit(1)
        if not args.key:
            print("[ERROR] Provide --key or set AZURE_CONTENT_SAFETY_KEY")
            sys.exit(1)

    # ── Load prompts ──────────────────────────────────────────────────────────
    inputs_path = Path(args.inputs)
    if not inputs_path.exists():
        print(f"[ERROR] Inputs file not found: {inputs_path}")
        sys.exit(1)

    prompts = load_prompts(inputs_path)
    if not prompts:
        print("[ERROR] No valid prompts found in inputs file.")
        sys.exit(1)

    print_header()
    print(f"\n  Loaded {len(prompts)} prompts from: {inputs_path}")
    print(f"  Thresholds to test: {args.thresholds}")
    print(f"  Dry run: {args.dry_run}")

    if args.dry_run:
        print("\n[DRY RUN] Prompts that would be tested:")
        for i, entry in enumerate(prompts, 1):
            print(f"  {i:>2}. [{entry['category']}|{entry['severity_label']}] {entry['prompt'][:80]}")
        return

    # ── Build client ──────────────────────────────────────────────────────────
    client = build_client(args.endpoint, args.key)

    # ── Run tests ─────────────────────────────────────────────────────────────
    all_results = []
    total = len(prompts)

    for idx, entry in enumerate(prompts, 1):
        print_prompt_block(idx, total, entry)

        scores = analyze_text(client, entry["prompt"])
        if not scores:
            print("  [SKIP] No scores returned (API error).")
            continue

        print_scores(scores)
        print_threshold_results(scores, args.thresholds)

        # Store flat rows for CSV/JSON
        for thresh in args.thresholds:
            flags = apply_threshold(scores, thresh)
            all_results.append(
                {
                    "prompt_idx": idx,
                    "category": entry["category"],
                    "severity_label": entry["severity_label"],
                    "prompt": entry["prompt"],
                    "hate_score": scores.get(TextCategory.HATE, 0),
                    "sexual_score": scores.get(TextCategory.SEXUAL, 0),
                    "violence_score": scores.get(TextCategory.VIOLENCE, 0),
                    "selfharm_score": scores.get(TextCategory.SELF_HARM, 0),
                    "threshold": thresh,
                    "hate_flagged": flags[TextCategory.HATE],
                    "sexual_flagged": flags[TextCategory.SEXUAL],
                    "violence_flagged": flags[TextCategory.VIOLENCE],
                    "selfharm_flagged": flags[TextCategory.SELF_HARM],
                }
            )

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{HEADER_SEP}")
    print(" SUMMARY")
    print(HEADER_SEP)

    for thresh in args.thresholds:
        rows = [r for r in all_results if r["threshold"] == thresh]
        flagged = sum(
            1 for r in rows
            if any([r["hate_flagged"], r["sexual_flagged"],
                    r["violence_flagged"], r["selfharm_flagged"]])
        )
        print(f"  Threshold ≥ {thresh}: {flagged}/{len(rows)} prompts triggered at least one flag")

    # ── Export ────────────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    save_csv(all_results, out_dir / f"results_{ts}.csv")
    save_json(all_results, out_dir / f"results_{ts}.json")

    print(f"\n{HEADER_SEP}")
    print(" Done.")
    print(HEADER_SEP)


if __name__ == "__main__":
    main()
