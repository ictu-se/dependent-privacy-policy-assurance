# Dependent Policy-Interaction Assurance Replication Package

This package contains the code, generated benchmark data, result tables, and figures needed to reproduce the dependent policy-interaction assurance experiment for secure API contracts.

The benchmark models policy faults that are invisible to independent schema, role, object, field, audit, and basic policy-aware checks unless the test oracle represents interactions among purpose, consent, jurisdiction, aggregation size, response fields, and audit evidence.

## Package Contents

- `src/dependent_policy_assurance/benchmark.py`: deterministic scenario generator, method simulators, metric computations, robustness analyses, and figure generation.
- `scripts/run_experiment.py`: command-line wrapper for rerunning the full experiment.
- `data/scenarios.jsonl`: generated benchmark scenarios for the default run.
- `results/`: generated judgments, summaries, ablations, robustness checks, workload estimates, and diagnostic case tables.
- `figures/`: generated PDF figures.
- `requirements.txt` and `pyproject.toml`: dependency and packaging metadata.

No manuscript source, manuscript PDF, journal template, cover letter, submission note, or local build artifact is included.

## Requirements

Python 3.10 or later is recommended.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Alternatively, install the package in editable mode:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Reproduce the Experiment

From the package root:

```bash
python3 scripts/run_experiment.py --replicas 10
```

or, after editable installation:

```bash
dependent-policy-benchmark --replicas 10
```

The default command regenerates:

- `data/scenarios.jsonl`
- all CSV and JSON files under `results/`
- all PDF figures under `figures/`

Expected default output:

- `578` benchmark scenarios
- `10,982` method-scenario judgments
- `19` evaluated methods

## Main Result Files

- `results/method_summary.csv`: precision, recall, specificity, F1, and risk-weighted recall by method.
- `results/judgments.csv`: row-level method-scenario judgments.
- `results/recall_by_violation_family.csv`: family-level violation recall.
- `results/benign_false_alarm.csv`: false-alarm rates on benign dependent-policy controls.
- `results/ablation_loss.csv`: recall and risk-weighted recall loss after clause-family ablation.
- `results/bootstrap_intervals.csv`: scenario-level bootstrap intervals.
- `results/weight_sensitivity.csv`: risk-weighted recall under alternative severity-weight schemes.
- `results/unknown_clause_sensitivity.csv`: adjusted coverage under unrepresented dependent-risk loads.
- `results/prevalence_workload.csv`: expected review workload at different violation prevalence levels.
- `results/escape_cases.csv`: diagnostic high-risk misses for incomplete methods.
- `results/suite_growth.csv`: compactness comparison between represented clauses and naive cross-products.

## Determinism

Scenario generation is deterministic. Bootstrap resampling uses a fixed seed. Re-running the default command should reproduce the distributed scenario count, judgment count, tables, and figures.

## Citation

If you use this package, cite the archived Zenodo record associated with this release.
