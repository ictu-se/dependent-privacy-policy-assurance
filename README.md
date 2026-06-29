# Dependent Privacy-Policy Assurance Benchmark

This repository contains the replication package for a deterministic benchmark of dependent privacy-policy testing in public-sector API assurance. The benchmark models policy failures that arise from interactions among role, object relation, jurisdiction, purpose, consent, aggregation threshold, response fields, and audit evidence.

## Contents

- `scripts/run_dependent_policy_experiment.py`: benchmark generator, method simulator, metric computation, and figure generation.
- `data/dependent_policy_scenarios.jsonl`: generated benchmark scenarios.
- `results/`: generated judgments, summary metrics, ablations, robustness checks, workload estimates, and diagnostic case tables.
- `figures/`: generated experiment figures.

No manuscript source or submission files are included in this replication package.

## Requirements

Python 3.10 or later is recommended. The core benchmark uses only the Python standard library. Figure generation uses `matplotlib`.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Reproduce The Study Outputs

From the repository root:

```bash
python3 scripts/run_dependent_policy_experiment.py --replicas 10
```

The command regenerates:

- `data/dependent_policy_scenarios.jsonl`
- all CSV and JSON files under `results/`
- all PDF figures under `figures/`

The expected default run creates 578 scenarios and 10,982 method-scenario judgments.

## Main Output Files

- `results/method_summary.csv`: precision, recall, specificity, F1, and risk-weighted recall by method.
- `results/ablation_loss.csv`: coverage loss after removing each dependent clause family.
- `results/bootstrap_intervals.csv`: scenario-level bootstrap intervals for selected methods.
- `results/weight_sensitivity.csv`: risk-weighted recall under alternative severity schemes.
- `results/unknown_clause_sensitivity.csv`: adjusted coverage under unrepresented dependent-risk loads.
- `results/prevalence_workload.csv`: expected alert workload at different violation prevalence levels.
- `results/escape_cases.csv`: representative high-risk misses for incomplete dependent suites.

## Determinism

The benchmark uses deterministic scenario construction and fixed random seeds for bootstrap resampling. Re-running the command above should reproduce the distributed results and figures.
