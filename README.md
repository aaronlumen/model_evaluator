###Author: Aaron Surina - LLM Reasoning Evaluator Tooling - Heads up:
# 2 files run the show;
> [!TIP] 
> eval_harness.py — the main engine. Runs all probes against your local Ollama models, uses one model as a judge to score the others (LLM-as-Judge pattern), and outputs everything.
> probe_builder.py — add your own proprietary security scenarios without touching the harness. Includes example probes already built for network recon, IP security agent reasoning, and OPSEC.

> [!INFO] Quickstart on your machine
> 

```
pip install -r requirements.txt

ollama pull mistral
ollama pull mixtral

python eval_harness.py --models mistral mixtral --judge mistral
```

### What gets output
```
eval_results/
├── eval_results.json        ← full probe responses + judge scores
├── eval_summary.csv         ← spreadsheet-ready comparison
├── eval_chart.png           ← bar chart + overall score comparison
└── report_mistral.md        ← per-model detailed breakdown
Key design decisions

Abductive and hallucination resistance are weighted 2× — those are the two failure modes that matter most for security agents making tool decisions
Temperature locked at 0.15 for evaluated models, 0.0 for the judge — keeps scoring deterministic
Fully air-gapped — nothing leaves localhost
The probe set is security-domain specific but the architecture is general — swap in your proprietary PoC scenarios via probe_builder.py

# LLM Reasoning Eval Harness — Security Domain

Evaluates local Ollama models across **7 reasoning categories** critical for
security agent and pentest tooling selection.

---

## Quick Start

```bash
# 1. Install dependencies
pip install ollama requests rich pandas matplotlib seaborn

# 2. Make sure Ollama is running
ollama serve

# 3. Pull some models to compare
ollama pull mistral
ollama pull mixtral
ollama pull deepseek-coder

# 4. Run the eval
python eval_harness.py --models mistral mixtral deepseek-coder

# 5. Run only specific categories
python eval_harness.py --models mistral --categories chain_of_thought abductive hallucination_resistance

# 6. Use a specific judge model
python eval_harness.py --models mixtral --judge mistral

# 7. List available models
python eval_harness.py --list-models
```

---

## Reasoning Categories Evaluated

| Category | Weight | What It Tests |
|---|---|---|
| `chain_of_thought` | 1.5× | Multi-step labeled reasoning |
| `abductive` | 2.0× | Evidence → root cause reasoning |
| `analogical` | 1.5× | Pattern transfer to novel surfaces |
| `counterfactual` | 1.0× | Hypothetical constraint reasoning |
| `causal_chain` | 1.5× | Multi-hop cause-effect tracing |
| `hallucination_resistance` | 2.0× | Technical fact accuracy |
| `self_correction` | 1.0× | Revision on contradicting evidence |

Weights reflect importance for **security agent + pentest** use cases.
Abductive reasoning and hallucination resistance are most critical.

---

## Outputs

```
eval_results/
├── eval_results.json          # Full raw results with all probe responses
├── eval_summary.csv           # Per-model per-category scores  
├── eval_chart.png             # Bar chart + overall score comparison
└── report_<modelname>.md      # Detailed per-model markdown report
```

---

## Custom Probes

Add your own proprietary security probes:

```bash
# Save example probes to probes/ directory
python probe_builder.py --save-examples

# Interactive probe creator
python probe_builder.py --create

# Validate your probe files
python probe_builder.py --validate
```

Probe files in `probes/*.json` are loaded automatically if you integrate
`probe_builder.load_probes()` into your workflow.

---

## Architecture

```
eval_harness.py
├── PROBES dict              ← all reasoning categories + probes
├── OllamaClient             ← thin wrapper around Ollama REST API
├── ReasoningEvaluator       ← runs probes, calls LLM-as-Judge
│   └── run_probe()          ← generate → judge → score
└── EvalReporter             ← JSON, CSV, charts, markdown reports

probe_builder.py
├── EXAMPLE_PROBES           ← network recon, IP security, OPSEC probes
├── create_probe_interactive ← CLI wizard
└── validate_probes()        ← schema checker
```

---

## Interpreting Scores

| Score | Meaning |
|---|---|
| 8–10 | Excellent — production-ready for this reasoning type |
| 6–8 | Good — usable with prompt engineering |
| 4–6 | Fair — needs fine-tuning for this domain |
| 0–4 | Poor — not suitable for security agent use |

**Overall weighted score** is your primary selection signal.
For security agents: prioritize `abductive` and `hallucination_resistance` sub-scores.

---

## Notes

- Judge model evaluates all other models — use your best local model as judge
- Temperature is fixed at 0.15 for evaluated models, 0.0 for judge
- All runs are local / air-gapped — no external API calls
- Extend `PROBES` in `eval_harness.py` with your proprietary scenarios
