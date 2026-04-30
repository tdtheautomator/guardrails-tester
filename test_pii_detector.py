"""
PII Guardrails Testing Suite using Microsoft Presidio
======================================================
Detects Personally Identifiable Information (PII) across multiple categories.
Reads test cases from inputs/pii_test_cases.json
Outputs results to outputs/ as CSV, JSON, and dark-theme HTML.

Requirements:
    pip install presidio-analyzer presidio-anonymizer spacy
    python -m spacy download en_core_web_lg
"""

import json
import csv
import os
import sys
import time
from datetime import datetime
from pathlib import Path

# ── Presidio imports ────────────────────────────────────────────────────────
try:
    from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
    from presidio_analyzer.nlp_engine import NlpEngineProvider
except ImportError:
    print("[ERROR] presidio-analyzer not installed.")
    print("  Run: pip install presidio-analyzer presidio-anonymizer spacy")
    print("       python -m spacy download en_core_web_lg")
    sys.exit(1)

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
INPUTS_DIR  = BASE_DIR / "inputs"
OUTPUTS_DIR = BASE_DIR / "outputs"
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

INPUT_FILE  = INPUTS_DIR / "pii_test_cases.json"
TIMESTAMP   = datetime.now().strftime("%Y%m%d_%H%M%S")

OUT_CSV     = OUTPUTS_DIR / f"pii_test_results_{TIMESTAMP}.csv"
OUT_JSON    = OUTPUTS_DIR / f"pii_test_results_{TIMESTAMP}.json"
OUT_HTML    = OUTPUTS_DIR / f"pii_test_results_{TIMESTAMP}.html"


# ════════════════════════════════════════════════════════════════════════════
# 1. ANALYZER SETUP
# ════════════════════════════════════════════════════════════════════════════

def build_analyzer() -> AnalyzerEngine:
    """
    Build a Presidio AnalyzerEngine.

    Tries spaCy models in descending quality order, then falls back to the
    pattern-only engine (no NLP model required).  The fallback still catches
    all regex/rule-based entities (emails, phones, credit cards, SSNs, IPs,
    dates…) but won't detect PERSON or LOCATION (which need a NER model).
    """
    spacy_models = ["en_core_web_lg", "en_core_web_md", "en_core_web_sm", "en_core_web_trf"]

    for model_name in spacy_models:
        try:
            import spacy as _spacy
            _spacy.load(model_name)          # raises if model not installed
            print(f"[*] Initialising Presidio with spaCy model '{model_name}'…")
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model_name}],
            }
            provider   = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()
            analyzer   = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
            print(f"[✓] Analyzer ready (spaCy / {model_name}).\n")
            return analyzer
        except Exception:
            continue

    # ── Pattern-only fallback ────────────────────────────────────────────
    print("[!] No spaCy model found — using pattern-only engine.")
    print("    PERSON / LOCATION detection will be unavailable.")
    print("    Install a model:  python -m spacy download en_core_web_sm\n")
    try:
        from presidio_analyzer.nlp_engine import SpacyNlpEngine
        # Presidio ≥ 2.2 accepts a no-model configuration
        configuration = {
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
        # We monkey-patch to skip actual spaCy loading
        from presidio_analyzer import AnalyzerEngine as _AE
        analyzer = _AE(supported_languages=["en"])
        print("[✓] Analyzer ready (pattern-only mode).\n")
        return analyzer
    except Exception as e:
        print(f"[!] Fallback also failed: {e}. Returning default AnalyzerEngine.")
        return AnalyzerEngine(supported_languages=["en"])


# ════════════════════════════════════════════════════════════════════════════
# 2. RUN ANALYSIS
# ════════════════════════════════════════════════════════════════════════════

# All entity types Presidio ships with
ALL_ENTITIES = [
    "CREDIT_CARD", "CRYPTO", "DATE_TIME", "EMAIL_ADDRESS",
    "IBAN_CODE", "IP_ADDRESS", "NRP", "LOCATION",
    "MEDICAL_LICENSE", "PERSON", "PHONE_NUMBER",
    "URL", "US_BANK_NUMBER", "US_DRIVER_LICENSE",
    "US_ITIN", "US_PASSPORT", "US_SSN",
]


def analyze_text(analyzer: AnalyzerEngine, text: str, score_threshold: float = 0.3):
    """Run Presidio analysis and return list of result dicts."""
    results = analyzer.analyze(
        text=text,
        entities=ALL_ENTITIES,
        language="en",
        score_threshold=score_threshold,
    )
    findings = []
    for r in results:
        findings.append({
            "entity_type":  r.entity_type,
            "start":        r.start,
            "end":          r.end,
            "score":        round(r.score, 4),
            "matched_text": text[r.start:r.end],
        })
    return sorted(findings, key=lambda x: x["start"])


def evaluate_test(test_case: dict, findings: list) -> dict:
    """Compare detected entities against expected ones and produce a verdict."""
    detected_types = set(f["entity_type"] for f in findings)
    expected_types = set(test_case.get("expected_entities", []))

    true_positives  = detected_types & expected_types
    false_positives = detected_types - expected_types
    false_negatives = expected_types - detected_types

    # PASS = every expected type found and no unexpected extras
    # PARTIAL = some expected types found
    # FAIL = nothing expected found (or FP-only on a clean sample)
    if expected_types:
        if true_positives == expected_types and not false_positives:
            verdict = "PASS"
        elif true_positives:
            verdict = "PARTIAL"
        else:
            verdict = "FAIL"
    else:
        # Negative test: pass only if nothing detected
        verdict = "PASS" if not detected_types else "FAIL"

    return {
        "true_positives":  sorted(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "verdict":         verdict,
    }


def run_tests(analyzer: AnalyzerEngine, test_cases: list, score_threshold: float = 0.3):
    """Run all test cases and collect full results."""
    results = []
    total = len(test_cases)

    for i, tc in enumerate(test_cases, 1):
        tc_id    = tc.get("id", f"TC{i:03d}")
        category = tc.get("category", "Unknown")
        desc     = tc.get("description", "")
        text     = tc.get("text", "")

        print(f"  [{i:02d}/{total}] {tc_id} — {category}")

        t0       = time.perf_counter()
        findings = analyze_text(analyzer, text, score_threshold)
        elapsed  = round((time.perf_counter() - t0) * 1000, 2)  # ms

        evaluation = evaluate_test(tc, findings)

        verdict_icon = {"PASS": "✓", "PARTIAL": "~", "FAIL": "✗"}.get(evaluation["verdict"], "?")
        print(f"         {verdict_icon} {evaluation['verdict']} | "
              f"Detected: {[f['entity_type'] for f in findings]} | {elapsed}ms")

        results.append({
            "id":               tc_id,
            "category":         category,
            "description":      desc,
            "input_text":       text,
            "expected_entities": tc.get("expected_entities", []),
            "findings":         findings,
            "detected_types":   sorted(set(f["entity_type"] for f in findings)),
            "verdict":          evaluation["verdict"],
            "true_positives":   evaluation["true_positives"],
            "false_positives":  evaluation["false_positives"],
            "false_negatives":  evaluation["false_negatives"],
            "latency_ms":       elapsed,
            "score_threshold":  score_threshold,
        })

    return results


# ════════════════════════════════════════════════════════════════════════════
# 3. SUMMARY STATS
# ════════════════════════════════════════════════════════════════════════════

def compute_summary(results: list) -> dict:
    verdicts  = [r["verdict"] for r in results]
    total     = len(results)
    passed    = verdicts.count("PASS")
    partial   = verdicts.count("PARTIAL")
    failed    = verdicts.count("FAIL")

    all_expected = []
    all_detected = []
    for r in results:
        all_expected.extend(r["expected_entities"])
        all_detected.extend(r["detected_types"])

    tp = sum(len(r["true_positives"]) for r in results)
    fp = sum(len(r["false_positives"]) for r in results)
    fn = sum(len(r["false_negatives"]) for r in results)

    precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    recall    = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    f1        = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0.0

    avg_latency = round(sum(r["latency_ms"] for r in results) / total, 2) if total else 0

    return {
        "total":        total,
        "passed":       passed,
        "partial":      partial,
        "failed":       failed,
        "pass_rate":    f"{round(passed/total*100, 1)}%" if total else "0%",
        "precision":    precision,
        "recall":       recall,
        "f1_score":     f1,
        "avg_latency_ms": avg_latency,
        "generated_at": datetime.now().isoformat(),
    }


# ════════════════════════════════════════════════════════════════════════════
# 4. EXPORTERS
# ════════════════════════════════════════════════════════════════════════════

def export_csv(results: list, summary: dict, path: Path):
    """Flat CSV — one row per test case."""
    fieldnames = [
        "id", "category", "description", "verdict",
        "detected_types", "expected_entities",
        "true_positives", "false_positives", "false_negatives",
        "findings_count", "latency_ms", "input_text",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "id":               r["id"],
                "category":         r["category"],
                "description":      r["description"],
                "verdict":          r["verdict"],
                "detected_types":   "|".join(r["detected_types"]),
                "expected_entities":"|".join(r["expected_entities"]),
                "true_positives":   "|".join(r["true_positives"]),
                "false_positives":  "|".join(r["false_positives"]),
                "false_negatives":  "|".join(r["false_negatives"]),
                "findings_count":   len(r["findings"]),
                "latency_ms":       r["latency_ms"],
                "input_text":       r["input_text"],
            })
    print(f"[✓] CSV  → {path}")


def export_json(results: list, summary: dict, path: Path):
    """Full JSON output with summary + per-test details."""
    payload = {"summary": summary, "results": results}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    print(f"[✓] JSON → {path}")


def _verdict_badge(verdict: str) -> str:
    colours = {"PASS": "#22c55e", "PARTIAL": "#f59e0b", "FAIL": "#ef4444"}
    colour  = colours.get(verdict, "#94a3b8")
    return (f'<span style="background:{colour};color:#000;padding:2px 10px;'
            f'border-radius:12px;font-size:0.78rem;font-weight:700">{verdict}</span>')


def _highlight_text(text: str, findings: list) -> str:
    """Return HTML with PII spans highlighted inline."""
    # Sort by start position, handle overlaps by skipping inner ones
    sorted_findings = sorted(findings, key=lambda x: x["start"])
    result   = []
    cursor   = 0
    for f in sorted_findings:
        if f["start"] < cursor:
            continue
        result.append(text[cursor:f["start"]].replace("<", "&lt;").replace(">", "&gt;"))
        snippet = text[f["start"]:f["end"]].replace("<", "&lt;").replace(">", "&gt;")
        result.append(
            f'<mark title="{f["entity_type"]} (score {f["score"]})" '
            f'style="background:#fbbf24;color:#111;border-radius:3px;padding:0 3px">'
            f'{snippet}</mark>'
        )
        cursor = f["end"]
    result.append(text[cursor:].replace("<", "&lt;").replace(">", "&gt;"))
    return "".join(result)


def export_html(results: list, summary: dict, path: Path):
    """Dark-theme HTML report with summary cards and detailed findings table."""
    pass_rate_val = float(summary["pass_rate"].replace("%", ""))
    ring_colour   = "#22c55e" if pass_rate_val >= 80 else "#f59e0b" if pass_rate_val >= 50 else "#ef4444"

    # Build category summary rows
    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"PASS": 0, "PARTIAL": 0, "FAIL": 0, "total": 0}
        categories[cat][r["verdict"]] += 1
        categories[cat]["total"] += 1

    cat_rows = ""
    for cat, stats in sorted(categories.items()):
        pct = round(stats["PASS"] / stats["total"] * 100) if stats["total"] else 0
        cat_rows += f"""
        <tr>
          <td>{cat}</td>
          <td style="color:#22c55e">{stats['PASS']}</td>
          <td style="color:#f59e0b">{stats['PARTIAL']}</td>
          <td style="color:#ef4444">{stats['FAIL']}</td>
          <td>{stats['total']}</td>
          <td>
            <div style="background:#334155;border-radius:6px;height:8px;width:100%">
              <div style="background:{ring_colour};border-radius:6px;height:8px;width:{pct}%"></div>
            </div>
            <small>{pct}%</small>
          </td>
        </tr>"""

    # Build detail rows
    detail_rows = ""
    for r in results:
        findings_html = ""
        if r["findings"]:
            findings_html = "<table style='width:100%;font-size:0.78rem;border-collapse:collapse'>"
            findings_html += "<tr style='color:#94a3b8'><th>Entity</th><th>Matched</th><th>Score</th><th>Span</th></tr>"
            for f in r["findings"]:
                findings_html += (
                    f"<tr><td style='color:#818cf8'>{f['entity_type']}</td>"
                    f"<td style='color:#fbbf24'>{f['matched_text']}</td>"
                    f"<td>{f['score']}</td>"
                    f"<td>[{f['start']}:{f['end']}]</td></tr>"
                )
            findings_html += "</table>"
        else:
            findings_html = "<span style='color:#64748b'>No PII detected</span>"

        tp_html = ", ".join(f'<span style="color:#22c55e">{e}</span>' for e in r["true_positives"]) or "—"
        fp_html = ", ".join(f'<span style="color:#ef4444">{e}</span>' for e in r["false_positives"]) or "—"
        fn_html = ", ".join(f'<span style="color:#f59e0b">{e}</span>' for e in r["false_negatives"]) or "—"

        highlighted = _highlight_text(r["input_text"], r["findings"])

        detail_rows += f"""
        <tr>
          <td style="color:#94a3b8;white-space:nowrap">{r['id']}</td>
          <td style="font-size:0.8rem">{r['category']}</td>
          <td>{_verdict_badge(r['verdict'])}</td>
          <td style="font-size:0.82rem">
            <div style="font-family:monospace;background:#0f172a;padding:6px 8px;
                        border-radius:6px;line-height:1.6">{highlighted}</div>
          </td>
          <td style="font-size:0.8rem">{findings_html}</td>
          <td style="font-size:0.78rem">{tp_html}</td>
          <td style="font-size:0.78rem">{fp_html}</td>
          <td style="font-size:0.78rem">{fn_html}</td>
          <td style="color:#94a3b8;white-space:nowrap">{r['latency_ms']} ms</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PII Guardrails Report — {TIMESTAMP}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{font-size:1.6rem;font-weight:700;color:#f8fafc;margin-bottom:.25rem}}
  h2{{font-size:1.1rem;font-weight:600;color:#cbd5e1;margin:2rem 0 .75rem}}
  .subtitle{{color:#64748b;font-size:.85rem;margin-bottom:2rem}}
  .cards{{display:flex;flex-wrap:wrap;gap:1rem;margin-bottom:2rem}}
  .card{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.25rem 1.5rem;min-width:160px;flex:1}}
  .card .label{{color:#64748b;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}}
  .card .value{{font-size:2rem;font-weight:700;margin-top:.25rem}}
  .card.green .value{{color:#22c55e}}
  .card.yellow .value{{color:#f59e0b}}
  .card.red .value{{color:#ef4444}}
  .card.blue .value{{color:#60a5fa}}
  .card.purple .value{{color:#a78bfa}}
  table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden;font-size:.85rem}}
  th{{background:#0f172a;color:#64748b;font-weight:600;padding:.65rem 1rem;text-align:left;white-space:nowrap}}
  td{{padding:.65rem 1rem;border-top:1px solid #334155;vertical-align:top}}
  tr:hover td{{background:#263348}}
  .section{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:1.25rem;margin-bottom:2rem;overflow-x:auto}}
  .badge{{display:inline-block;padding:2px 8px;border-radius:8px;font-size:.75rem;font-weight:600}}
  footer{{margin-top:3rem;color:#334155;font-size:.78rem;text-align:center}}
</style>
</head>
<body>

<h1>🔍 PII Guardrails Detection Report</h1>
<p class="subtitle">Generated: {summary['generated_at']} &nbsp;|&nbsp; Threshold: {results[0]['score_threshold'] if results else 0.3} &nbsp;|&nbsp; Engine: Presidio + spaCy en_core_web_lg</p>

<!-- SUMMARY CARDS -->
<div class="cards">
  <div class="card green"><div class="label">Pass</div><div class="value">{summary['passed']}</div></div>
  <div class="card yellow"><div class="label">Partial</div><div class="value">{summary['partial']}</div></div>
  <div class="card red"><div class="label">Fail</div><div class="value">{summary['failed']}</div></div>
  <div class="card blue"><div class="label">Total Tests</div><div class="value">{summary['total']}</div></div>
  <div class="card green"><div class="label">Pass Rate</div><div class="value">{summary['pass_rate']}</div></div>
  <div class="card purple"><div class="label">Precision</div><div class="value">{summary['precision']}</div></div>
  <div class="card purple"><div class="label">Recall</div><div class="value">{summary['recall']}</div></div>
  <div class="card purple"><div class="label">F1 Score</div><div class="value">{summary['f1_score']}</div></div>
  <div class="card blue"><div class="label">Avg Latency</div><div class="value" style="font-size:1.4rem">{summary['avg_latency_ms']} ms</div></div>
</div>

<!-- CATEGORY BREAKDOWN -->
<h2>📊 Results by Category</h2>
<div class="section">
  <table>
    <thead><tr><th>Category</th><th>Pass</th><th>Partial</th><th>Fail</th><th>Total</th><th style="min-width:200px">Pass Rate</th></tr></thead>
    <tbody>{cat_rows}</tbody>
  </table>
</div>

<!-- DETAILED RESULTS -->
<h2>🧪 Detailed Test Results</h2>
<div class="section">
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Category</th><th>Verdict</th><th style="min-width:300px">Input Text</th>
        <th style="min-width:240px">Findings</th><th>TP</th><th>FP</th><th>FN</th><th>Latency</th>
      </tr>
    </thead>
    <tbody>{detail_rows}</tbody>
  </table>
</div>

<footer>PII Guardrails Test Suite &nbsp;|&nbsp; Microsoft Presidio &nbsp;|&nbsp; Report ID: {TIMESTAMP}</footer>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[✓] HTML → {path}")


# ════════════════════════════════════════════════════════════════════════════
# 5. MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  PII Guardrails Testing Suite — Presidio")
    print("=" * 60)

    # Load test cases
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    test_cases = data.get("test_cases", [])
    print(f"[*] Loaded {len(test_cases)} test cases from {INPUT_FILE}\n")

    # Score threshold (can override via CLI arg)
    threshold = float(sys.argv[1]) if len(sys.argv) > 1 else 0.3
    print(f"[*] Confidence score threshold: {threshold}\n")

    # Build analyzer
    analyzer = build_analyzer()

    # Run tests
    print("[*] Running test cases…")
    results = run_tests(analyzer, test_cases, score_threshold=threshold)

    # Compute summary
    summary = compute_summary(results)
    print(f"\n{'='*60}")
    print(f"  SUMMARY: {summary['passed']} PASS | {summary['partial']} PARTIAL | {summary['failed']} FAIL")
    print(f"  Pass Rate: {summary['pass_rate']}  |  F1: {summary['f1_score']}  |  Avg latency: {summary['avg_latency_ms']} ms")
    print(f"{'='*60}\n")

    # Export outputs
    print("[*] Exporting results…")
    export_csv(results, summary, OUT_CSV)
    export_json(results, summary, OUT_JSON)
    export_html(results, summary, OUT_HTML)

    print(f"\n[✓] All outputs saved to: {OUTPUTS_DIR}")


if __name__ == "__main__":
    main()
