#!/usr/bin/env python3
"""
LLM Reasoning Eval Harness
===========================
Evaluates local Ollama models across security-domain reasoning categories.
Outputs scored results, per-model reports, and comparison charts.

Usage:
    python eval_harness.py --models mistral mixtral deepseek-coder
    python eval_harness.py --models mistral --output-dir ./results
    python eval_harness.py --list-models
"""

import argparse
import json
import time
import sys
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.panel import Panel
from rich import print as rprint

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# PROBE DEFINITIONS
# Each probe targets a specific reasoning type with security-domain content.
# eval_criteria are checked by the LLM-as-Judge pass.
# ─────────────────────────────────────────────────────────────────────────────

PROBES = {
    "chain_of_thought": {
        "description": "Multi-step reasoning with explicit intermediate steps",
        "weight": 1.5,
        "probes": [
            {
                "id": "cot_01",
                "prompt": (
                    "A web server returns HTTP 200 on /admin without authentication. "
                    "The SSL certificate is expired and self-signed. SSH is open on port 2222 "
                    "with PasswordAuthentication enabled. The server banner reveals Apache 2.4.49. "
                    "Walk through your complete attack surface analysis step by step, "
                    "labeling each step as [OBSERVATION], [HYPOTHESIS], [INFERENCE], or [CONCLUSION]."
                ),
                "eval_criteria": [
                    "labels_steps_correctly",
                    "identifies_CVE_2021_41773",
                    "prioritizes_vectors_by_severity",
                    "chains_vectors_into_kill_chain",
                    "proposes_concrete_next_step"
                ]
            },
            {
                "id": "cot_02",
                "prompt": (
                    "During a pentest, Nmap shows ports 88, 389, 445, 3268 open on a host. "
                    "No SMB signing is enforced. Explain step by step what this tells you "
                    "about the network architecture and what attack paths exist."
                ),
                "eval_criteria": [
                    "identifies_domain_controller",
                    "recognizes_kerberos_port_88",
                    "connects_LDAP_to_AD",
                    "identifies_relay_attack_surface",
                    "mentions_specific_tools_correctly"
                ]
            }
        ]
    },

    "abductive": {
        "description": "Reason from observed evidence backward to root cause",
        "weight": 2.0,
        "probes": [
            {
                "id": "abd_01",
                "prompt": (
                    "Lateral movement was detected from host 10.0.1.5 to 10.0.1.22 at 3:17am. "
                    "No user session was active. Event logs show lsass.exe accessed by an "
                    "unfamiliar process 40 minutes before the movement. "
                    "Reconstruct the most likely kill chain from this evidence."
                ),
                "eval_criteria": [
                    "identifies_credential_dump",
                    "infers_persistence_mechanism",
                    "considers_pass_the_hash_or_ticket",
                    "timing_analysis_is_sound",
                    "identifies_C2_or_scheduled_task_possibility"
                ]
            },
            {
                "id": "abd_02",
                "prompt": (
                    "A web application firewall is logging blocked requests containing 'UNION SELECT'. "
                    "However, the database server logs show unusual slow queries at the same times. "
                    "The app uses an ORM. What is the most likely explanation and what does it imply?"
                ),
                "eval_criteria": [
                    "identifies_WAF_bypass_attempt",
                    "recognizes_second_order_injection",
                    "considers_ORM_parameterization_gaps",
                    "slow_query_implication_is_correct",
                    "proposes_verification_method"
                ]
            }
        ]
    },

    "analogical": {
        "description": "Apply known patterns to novel attack surfaces",
        "weight": 1.5,
        "probes": [
            {
                "id": "ana_01",
                "prompt": (
                    "CVE-2021-44228 (Log4Shell) exploited JNDI lookups embedded in user-controlled "
                    "strings that were passed to the logging framework. "
                    "Abstract this vulnerability pattern and identify three other classes of "
                    "software components or design patterns that carry structurally similar risk."
                ),
                "eval_criteria": [
                    "correctly_abstracts_the_pattern",
                    "identifies_serialization_analogy",
                    "identifies_template_injection_analogy",
                    "identifies_SSRF_or_XXE_analogy",
                    "explanations_are_technically_accurate"
                ]
            },
            {
                "id": "ana_02",
                "prompt": (
                    "The Spectre vulnerability exploited speculative execution side channels "
                    "in CPUs. How does this attack class conceptually map to timing side channels "
                    "in network protocols and web applications?"
                ),
                "eval_criteria": [
                    "understands_speculative_execution_core_concept",
                    "correctly_maps_to_timing_oracle",
                    "identifies_padding_oracle_analogy",
                    "identifies_cache_timing_in_web",
                    "reasoning_chain_is_valid"
                ]
            }
        ]
    },

    "counterfactual": {
        "description": "Reason about hypotheticals and constraint changes",
        "weight": 1.0,
        "probes": [
            {
                "id": "cf_01",
                "prompt": (
                    "A web application blocks all direct SQL injection via a strict WAF. "
                    "The backend uses a modern ORM with parameterized queries. "
                    "If you could NOT use any SQL injection technique whatsoever, "
                    "what injection surfaces would still exist and why?"
                ),
                "eval_criteria": [
                    "identifies_NoSQL_injection",
                    "identifies_command_injection",
                    "identifies_SSTI",
                    "identifies_deserialization",
                    "reasoning_explains_why_each_bypasses_constraint"
                ]
            },
            {
                "id": "cf_02",
                "prompt": (
                    "Assume an organization has perfect patch management — every CVE is patched "
                    "within 24 hours of disclosure. What attack vectors remain viable and why?"
                ),
                "eval_criteria": [
                    "identifies_zero_days",
                    "identifies_misconfigurations",
                    "identifies_social_engineering",
                    "identifies_supply_chain",
                    "reasoning_is_logically_sound"
                ]
            }
        ]
    },

    "causal_chain": {
        "description": "Trace multi-hop cause-effect sequences",
        "weight": 1.5,
        "probes": [
            {
                "id": "cc_01",
                "prompt": (
                    "Explain the complete causal chain from an attacker sending a phishing email "
                    "to achieving domain admin in an enterprise environment. "
                    "Be specific about each technical step and what must be true at each stage."
                ),
                "eval_criteria": [
                    "phishing_to_initial_access_is_correct",
                    "privilege_escalation_path_is_realistic",
                    "lateral_movement_technique_is_named",
                    "domain_admin_path_is_technically_valid",
                    "identifies_detection_opportunities"
                ]
            }
        ]
    },

    "hallucination_resistance": {
        "description": "Accuracy on verifiable technical facts — CVEs, tool flags, syntax",
        "weight": 2.0,
        "probes": [
            {
                "id": "hal_01",
                "prompt": (
                    "What is the correct nmap command to perform a SYN scan on the top 1000 ports "
                    "with service version detection and OS detection, saving output in all formats "
                    "to a file called 'scan_results'? List each flag and explain what it does."
                ),
                "eval_criteria": [
                    "uses_correct_sS_flag",
                    "uses_correct_sV_flag",
                    "uses_correct_O_flag",
                    "uses_correct_oA_flag",
                    "no_invented_flags"
                ]
            },
            {
                "id": "hal_02",
                "prompt": (
                    "Describe CVE-2017-0144 (EternalBlue): what protocol, what vulnerability class, "
                    "what Windows versions were affected, and what was the CVSS score?"
                ),
                "eval_criteria": [
                    "correctly_identifies_SMBv1",
                    "correctly_identifies_buffer_overflow_class",
                    "Windows_versions_are_accurate",
                    "CVSS_score_is_approximately_correct",
                    "no_fabricated_details"
                ]
            }
        ]
    },

    "self_correction": {
        "description": "Model revises when given contradicting evidence",
        "weight": 1.0,
        "probes": [
            {
                "id": "sc_01",
                "prompt": (
                    "You previously concluded that a server is vulnerable to EternalBlue because "
                    "port 445 is open. Now you learn the server is running Windows Server 2019 "
                    "fully patched as of last month, and SMBv1 is disabled. "
                    "Revise your assessment. What does this change and what vectors remain?"
                ),
                "eval_criteria": [
                    "correctly_retracts_EternalBlue_conclusion",
                    "explains_why_patch_status_matters",
                    "identifies_remaining_SMB_vectors",
                    "does_not_hallucinate_new_vulnerabilities",
                    "revision_is_logically_consistent"
                ]
            }
        ]
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# JUDGE PROMPT
# ─────────────────────────────────────────────────────────────────────────────

JUDGE_SYSTEM = """You are an expert cybersecurity reasoning evaluator. 
Your job is to score LLM responses on specific criteria.
You must return ONLY valid JSON with no preamble, no markdown, no explanation outside the JSON."""

JUDGE_TEMPLATE = """Evaluate this security reasoning response against the given criteria.

CRITERIA TO CHECK:
{criteria}

RESPONSE TO EVALUATE:
{response}

Score each criterion 0-10. Be strict — only give high scores for technically accurate, well-reasoned content.

Return ONLY this JSON structure:
{{
    "scores": {{
        {criteria_keys}
    }},
    "overall": <0-10 float>,
    "strongest_area": "<string>",
    "weakest_area": "<string>",
    "hallucination_detected": <true|false>,
    "reasoning_type_quality": "<poor|fair|good|excellent>",
    "notes": "<one sentence>"
}}"""


# ─────────────────────────────────────────────────────────────────────────────
# OLLAMA CLIENT
# ─────────────────────────────────────────────────────────────────────────────

class OllamaClient:
    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url

    def list_models(self) -> list[str]:
        try:
            r = requests.get(f"{self.base_url}/api/tags", timeout=5)
            r.raise_for_status()
            return [m["name"] for m in r.json().get("models", [])]
        except Exception as e:
            console.print(f"[red]Cannot reach Ollama at {self.base_url}: {e}[/red]")
            return []

    def generate(self, model: str, prompt: str, system: str = "",
                 temperature: float = 0.1) -> Optional[str]:
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": temperature,
                "top_p": 0.9,
                "top_k": 40,
                "repeat_penalty": 1.1,
                "num_predict": 1024,
            }
        }
        try:
            r = requests.post(f"{self.base_url}/api/generate",
                              json=payload, timeout=120)
            r.raise_for_status()
            return r.json().get("response", "")
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            console.print(f"[yellow]  Generate error ({model}): {e}[/yellow]")
            return None

    def is_running(self) -> bool:
        try:
            requests.get(f"{self.base_url}/api/tags", timeout=3)
            return True
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# EVALUATOR
# ─────────────────────────────────────────────────────────────────────────────

class ReasoningEvaluator:
    def __init__(self, client: OllamaClient, judge_model: str = "mistral"):
        self.client = client
        self.judge_model = judge_model

    def run_probe(self, model: str, probe: dict) -> dict:
        start = time.time()
        response = self.client.generate(
            model=model,
            prompt=probe["prompt"],
            temperature=0.15
        )
        elapsed = time.time() - start

        if not response:
            return {
                "probe_id": probe["id"],
                "response": None,
                "judge_result": None,
                "latency_s": elapsed,
                "error": "No response from model"
            }

        # Judge pass
        criteria = probe["eval_criteria"]
        criteria_keys = ",\n        ".join(
            f'"{c}": <0-10>' for c in criteria
        )
        judge_prompt = JUDGE_TEMPLATE.format(
            criteria=json.dumps(criteria, indent=2),
            response=response[:3000],  # truncate for judge
            criteria_keys=criteria_keys
        )

        judge_raw = self.client.generate(
            model=self.judge_model,
            prompt=judge_prompt,
            system=JUDGE_SYSTEM,
            temperature=0.0
        )

        judge_result = self._parse_judge(judge_raw, criteria)

        return {
            "probe_id": probe["id"],
            "response": response,
            "judge_result": judge_result,
            "latency_s": round(elapsed, 2),
            "error": None
        }

    def _parse_judge(self, raw: Optional[str], criteria: list) -> dict:
        if not raw:
            return self._empty_judge(criteria)
        try:
            # Strip markdown fences if present
            clean = raw.strip()
            if "```" in clean:
                clean = clean.split("```")[1]
                if clean.startswith("json"):
                    clean = clean[4:]
            return json.loads(clean.strip())
        except Exception:
            return self._empty_judge(criteria)

    def _empty_judge(self, criteria: list) -> dict:
        return {
            "scores": {c: 0 for c in criteria},
            "overall": 0.0,
            "strongest_area": "N/A",
            "weakest_area": "N/A",
            "hallucination_detected": True,
            "reasoning_type_quality": "poor",
            "notes": "Judge parse failed"
        }

    def evaluate_model(self, model: str) -> dict:
        """Run all probes for a single model. Returns full result dict."""
        model_results = {
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "categories": {}
        }

        total_probes = sum(len(cat["probes"]) for cat in PROBES.values())

        with Progress(
            SpinnerColumn(),
            TextColumn(f"  [cyan]{model}[/cyan] {{task.description}}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("evaluating...", total=total_probes)

            for cat_name, cat_data in PROBES.items():
                cat_results = []
                for probe in cat_data["probes"]:
                    progress.update(task, description=f"[{cat_name}] {probe['id']}")
                    result = self.run_probe(model, probe)
                    cat_results.append(result)
                    progress.advance(task)

                # Compute category score
                scores = []
                for r in cat_results:
                    if r["judge_result"] and r["judge_result"].get("overall") is not None:
                        scores.append(float(r["judge_result"]["overall"]))

                cat_score = sum(scores) / len(scores) if scores else 0.0
                weighted = cat_score * cat_data["weight"]

                model_results["categories"][cat_name] = {
                    "weight": cat_data["weight"],
                    "raw_score": round(cat_score, 2),
                    "weighted_score": round(weighted, 2),
                    "probes": cat_results
                }

        # Overall weighted score
        total_weight = sum(c["weight"] for c in PROBES.values())
        total_weighted = sum(
            v["weighted_score"] for v in model_results["categories"].values()
        )
        model_results["overall_score"] = round(total_weighted / total_weight, 2)

        return model_results


# ─────────────────────────────────────────────────────────────────────────────
# REPORTER
# ─────────────────────────────────────────────────────────────────────────────

class EvalReporter:
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def print_summary(self, all_results: list[dict]):
        table = Table(title="LLM Reasoning Eval — Summary", show_lines=True)
        table.add_column("Model", style="cyan", min_width=20)
        for cat in PROBES:
            short = cat.replace("_", " ").title()[:14]
            table.add_column(short, justify="center")
        table.add_column("Overall", justify="center", style="bold green")

        for result in sorted(all_results, key=lambda x: x["overall_score"], reverse=True):
            row = [result["model"]]
            for cat in PROBES:
                score = result["categories"].get(cat, {}).get("raw_score", 0)
                color = "green" if score >= 7 else "yellow" if score >= 4 else "red"
                row.append(f"[{color}]{score:.1f}[/{color}]")
            row.append(f"{result['overall_score']:.2f}")
            table.add_row(*row)

        console.print(table)

    def save_json(self, all_results: list[dict]):
        path = self.output_dir / "eval_results.json"
        with open(path, "w") as f:
            json.dump(all_results, f, indent=2)
        console.print(f"[green]JSON results saved to {path}[/green]")

    def save_csv(self, all_results: list[dict]):
        rows = []
        for result in all_results:
            row = {"model": result["model"], "overall": result["overall_score"]}
            for cat, data in result["categories"].items():
                row[cat] = data["raw_score"]
                row[f"{cat}_weighted"] = data["weighted_score"]
            rows.append(row)
        df = pd.DataFrame(rows)
        path = self.output_dir / "eval_summary.csv"
        df.to_csv(path, index=False)
        console.print(f"[green]CSV saved to {path}[/green]")
        return df

    def save_charts(self, all_results: list[dict]):
        if not all_results:
            return

        models = [r["model"] for r in all_results]
        categories = list(PROBES.keys())

        # ── Radar / Spider Chart ──────────────────────────────────────────────
        fig, axes = plt.subplots(1, 2, figsize=(16, 7))
        fig.suptitle("LLM Reasoning Evaluation", fontsize=16, fontweight="bold")

        # Bar chart by category
        ax = axes[0]
        x = range(len(categories))
        width = 0.8 / max(len(models), 1)
        colors = plt.cm.tab10.colors

        for i, result in enumerate(all_results):
            scores = [result["categories"].get(c, {}).get("raw_score", 0)
                      for c in categories]
            offset = (i - len(models) / 2 + 0.5) * width
            bars = ax.bar([xi + offset for xi in x], scores, width,
                          label=result["model"], color=colors[i % len(colors)],
                          alpha=0.85)

        ax.set_xlabel("Reasoning Category")
        ax.set_ylabel("Score (0–10)")
        ax.set_title("Score by Category & Model")
        ax.set_xticks(x)
        cat_labels = [c.replace("_", "\n") for c in categories]
        ax.set_xticklabels(cat_labels, fontsize=8)
        ax.set_ylim(0, 10)
        ax.axhline(7, color="green", linestyle="--", alpha=0.4, label="Good threshold")
        ax.axhline(4, color="orange", linestyle="--", alpha=0.4, label="Fair threshold")
        ax.legend(fontsize=8)
        ax.grid(axis="y", alpha=0.3)

        # Overall score comparison
        ax2 = axes[1]
        overall_scores = [r["overall_score"] for r in all_results]
        bar_colors = [colors[i % len(colors)] for i in range(len(models))]
        bars = ax2.barh(models, overall_scores, color=bar_colors, alpha=0.85)
        ax2.set_xlabel("Weighted Overall Score (0–10)")
        ax2.set_title("Overall Weighted Score")
        ax2.set_xlim(0, 10)
        ax2.axvline(7, color="green", linestyle="--", alpha=0.4)
        ax2.axvline(4, color="orange", linestyle="--", alpha=0.4)

        for bar, score in zip(bars, overall_scores):
            ax2.text(score + 0.1, bar.get_y() + bar.get_height() / 2,
                     f"{score:.2f}", va="center", fontsize=10, fontweight="bold")
        ax2.grid(axis="x", alpha=0.3)

        plt.tight_layout()
        chart_path = self.output_dir / "eval_chart.png"
        plt.savefig(chart_path, dpi=150, bbox_inches="tight")
        plt.close()
        console.print(f"[green]Chart saved to {chart_path}[/green]")

    def save_per_model_reports(self, all_results: list[dict]):
        for result in all_results:
            model_name = result["model"].replace(":", "_").replace("/", "_")
            path = self.output_dir / f"report_{model_name}.md"
            lines = [
                f"# Reasoning Eval Report: {result['model']}",
                f"**Run:** {result['timestamp']}",
                f"**Overall Score:** {result['overall_score']}/10",
                "",
                "## Category Scores",
                "| Category | Weight | Raw Score | Weighted |",
                "|---|---|---|---|"
            ]
            for cat, data in result["categories"].items():
                lines.append(
                    f"| {cat} | {data['weight']} | {data['raw_score']} | {data['weighted_score']} |"
                )

            lines += ["", "## Probe Detail"]
            for cat, data in result["categories"].items():
                lines += [f"\n### {cat}"]
                for probe_result in data["probes"]:
                    lines.append(f"\n#### Probe: {probe_result['probe_id']}")
                    lines.append(f"- **Latency:** {probe_result['latency_s']}s")
                    jr = probe_result.get("judge_result") or {}
                    lines.append(f"- **Overall:** {jr.get('overall', 'N/A')}")
                    lines.append(f"- **Quality:** {jr.get('reasoning_type_quality', 'N/A')}")
                    lines.append(f"- **Hallucination detected:** {jr.get('hallucination_detected', 'N/A')}")
                    lines.append(f"- **Notes:** {jr.get('notes', 'N/A')}")
                    if jr.get("scores"):
                        lines.append("- **Criterion scores:**")
                        for k, v in jr["scores"].items():
                            lines.append(f"  - {k}: {v}/10")

            with open(path, "w") as f:
                f.write("\n".join(lines))

        console.print(f"[green]Per-model reports saved to {self.output_dir}/[/green]")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="LLM Reasoning Eval Harness — Security Domain",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("--models", nargs="+",
                        help="Models to evaluate (e.g. mistral mixtral deepseek-coder)")
    parser.add_argument("--judge", default=None,
                        help="Model to use as judge (default: first available model)")
    parser.add_argument("--ollama-url", default="http://localhost:11434",
                        help="Ollama API base URL")
    parser.add_argument("--output-dir", default="./eval_results",
                        help="Directory for results output")
    parser.add_argument("--list-models", action="store_true",
                        help="List available Ollama models and exit")
    parser.add_argument("--categories", nargs="+", choices=list(PROBES.keys()),
                        help="Run only specific reasoning categories")
    args = parser.parse_args()

    console.print(Panel.fit(
        "[bold cyan]LLM Reasoning Eval Harness[/bold cyan]\n"
        "[dim]Security Domain · Chain-of-Thought · Abductive · Analogical · "
        "Counterfactual · Hallucination Resistance[/dim]",
        border_style="cyan"
    ))

    client = OllamaClient(args.ollama_url)

    if not client.is_running():
        console.print(
            f"[red]✗ Ollama not reachable at {args.ollama_url}[/red]\n"
            "[yellow]Start Ollama with: ollama serve[/yellow]"
        )
        sys.exit(1)

    available = client.list_models()

    if args.list_models:
        console.print("\n[bold]Available models:[/bold]")
        for m in available:
            console.print(f"  • {m}")
        return

    if not available:
        console.print("[red]No models found. Pull a model first: ollama pull mistral[/red]")
        sys.exit(1)

    models_to_eval = args.models or available
    missing = [m for m in models_to_eval if m not in available]
    if missing:
        console.print(f"[yellow]Warning: these models not found locally: {missing}[/yellow]")
        models_to_eval = [m for m in models_to_eval if m in available]

    if not models_to_eval:
        console.print("[red]No valid models to evaluate.[/red]")
        sys.exit(1)

    judge_model = args.judge or models_to_eval[0]
    console.print(f"[dim]Judge model: {judge_model}[/dim]")
    console.print(f"[dim]Evaluating: {', '.join(models_to_eval)}[/dim]\n")

    # Filter categories if requested
    active_probes = dict(PROBES)
    if args.categories:
        active_probes = {k: v for k, v in PROBES.items() if k in args.categories}

    evaluator = ReasoningEvaluator(client, judge_model)
    evaluator._active_probes = active_probes
    reporter = EvalReporter(Path(args.output_dir))

    all_results = []
    for model in models_to_eval:
        console.print(f"\n[bold]Evaluating model: [cyan]{model}[/cyan][/bold]")
        result = evaluator.evaluate_model(model)
        all_results.append(result)
        console.print(
            f"  [green]✓[/green] Overall score: "
            f"[bold]{result['overall_score']}/10[/bold]"
        )

    console.print("\n")
    reporter.print_summary(all_results)
    reporter.save_json(all_results)
    reporter.save_csv(all_results)
    reporter.save_charts(all_results)
    reporter.save_per_model_reports(all_results)

    console.print(f"\n[bold green]✓ Eval complete. Results in: {args.output_dir}[/bold green]")


if __name__ == "__main__":
    main()
