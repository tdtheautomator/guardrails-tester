"""
Azure Content Safety SDK — Test Script
=======================================
Tests each prompt in acs_test_cases.txt against all four harm categories
(Hate, Sexual, Violence, SelfHarm) using multiple threshold combinations.

Requirements:
    pip install azure-ai-contentsafety azure-core python-dotenv

Usage:
    Create a `.env` file or set environment variables, then run:
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
from html import escape
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

INPUTS_FILE = Path(__file__).parent / "inputs" / "acs_test_cases.txt"

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
    """Parse acs_test_cases.txt → list of {category, severity_label, prompt}."""
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


def save_html(results: list[dict], path: Path):
    rows = []
    for result in results:
        rows.append(
            "      <tr>"
            f"<td>{result['prompt_idx']}</td>"
            f"<td>{escape(result['category'])}</td>"
            f"<td>{escape(result['severity_label'])}</td>"
            f"<td class=\"prompt-cell\">{escape(result['prompt'])}</td>"
            f"<td>{result['hate_score']}</td>"
            f"<td>{result['sexual_score']}</td>"
            f"<td>{result['violence_score']}</td>"
            f"<td>{result['selfharm_score']}</td>"
            f"<td>{result['threshold']}</td>"
            f"<td class=\"{'flagged' if result['hate_flagged'] else 'passed'}\">{'🚫' if result['hate_flagged'] else '✅'}</td>"
            f"<td class=\"{'flagged' if result['sexual_flagged'] else 'passed'}\">{'🚫' if result['sexual_flagged'] else '✅'}</td>"
            f"<td class=\"{'flagged' if result['violence_flagged'] else 'passed'}\">{'🚫' if result['violence_flagged'] else '✅'}</td>"
            f"<td class=\"{'flagged' if result['selfharm_flagged'] else 'passed'}\">{'🚫' if result['selfharm_flagged'] else '✅'}</td>"
            "</tr>"
        )

    html_doc = f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<title>Content Safety Results</title>
<style>
body {{ background:#0c0f18; color:#e8eefb; font-family:Segoe UI,Arial,sans-serif; margin:0; padding:24px; }}
header {{ margin-bottom:20px; }}
h1 {{ font-size:1.9rem; margin:0 0 8px; color:#f7fbff; }}
p {{ margin:0; color:#b8c5e0; }}
table {{ width:100%; border-collapse:collapse; background:#141a2e; box-shadow:0 20px 50px rgba(0,0,0,0.45); margin-top:18px; }}
th, td {{ padding:12px 14px; text-align:left; border-bottom:1px solid #1f2640; }}
th {{ background:#1d2542; color:#eff6ff; position:sticky; top:0; z-index:2; }}
tbody tr:nth-child(even) {{ background:#111528; }}
tbody tr:hover {{ background:#1e2945; }}
.prompt-cell {{ max-width:520px; white-space:pre-wrap; word-break:break-word; }}
.flagged {{ color:#ff758f; font-weight:700; }}
.passed {{ color:#7be29a; font-weight:700; }}
</style>
</head>
<body>
<header>
<h1>Content Safety Results</h1>
<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</header>
<table>
<thead>
<tr>
<th>#</th><th>Category</th><th>Expected</th><th>Prompt</th><th>Hate</th><th>Sexual</th><th>Violence</th><th>SelfHarm</th><th>Threshold</th><th>Hate</th><th>Sexual</th><th>Violence</th><th>SelfHarm</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print(f"[EXPORT] HTML saved → {path}")


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
        help="Path to acs_test_cases.txt (default: ./inputs/acs_test_cases.txt)",
    )
    parser.add_argument(
        "--thresholds",
        nargs="+",
        type=int,
        default=THRESHOLDS_TO_TEST,
        help="Threshold values to test (default: 0 2 4 5 6 7)",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path(__file__).parent / "outputs"),
        help="Directory to save CSV/JSON/HTML results (default: ./outputs)",
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
    save_csv(all_results, out_dir / f"acs_test_results_{ts}.csv")
    save_json(all_results, out_dir / f"acs_test_results_{ts}.json")
    save_html(all_results, out_dir / f"acs_test_results_{ts}.html")

    print(f"\n{HEADER_SEP}")
    print(" Done.")
    print(HEADER_SEP)


if __name__ == "__main__":
    main()
