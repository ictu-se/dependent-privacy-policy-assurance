#!/usr/bin/env python3
"""Dependent privacy-policy testing benchmark for paper 07.

The experiment creates a deterministic benchmark of public-sector API
request-response observations whose failures require interaction clauses:
purpose-field, jurisdiction-field, consent-field, aggregation threshold,
enhanced audit, and compound consent-purpose-scope rules.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import random
from dataclasses import asdict, dataclass
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT / "data"
RESULTS_DIR = PROJECT / "results"
FIGURES_DIR = PROJECT / "figures"


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    replica: int
    domain: str
    endpoint: str
    role: str
    purpose: str
    field_family: str
    same_jurisdiction: bool
    object_relation: bool
    consent_active: bool
    consent_scope_valid: bool
    emergency: bool
    group_size: int
    returned_fields: tuple[str, ...]
    aggregate_returned: bool
    audit_marker: str
    violation_family: str
    expected_violation: bool
    expected_behavior: str
    risk: float


METHOD_CAPABILITIES = {
    "schema_validation": set(),
    "role_matrix": {"role"},
    "object_policy_tests": {"role", "object", "jurisdiction"},
    "field_policy_tests": {"field_static"},
    "audit_contract_tests": {"audit_basic"},
    "aggregation_only_tests": {"aggregation_threshold"},
    "basic_policy_aware_full": {"role", "object", "jurisdiction", "field_static", "audit_basic"},
    "purpose_field_contract_tests": {"purpose_field"},
    "consent_scope_contract_tests": {"consent_field"},
    "jurisdiction_redaction_tests": {"jurisdiction_field"},
    "pairwise_dependency_suite": {"purpose_field", "jurisdiction_field", "consent_field", "aggregation_threshold", "enhanced_audit"},
    "risk_heuristic_privacy_linter": {"risk_heuristic"},
    "keyword_sensitive_privacy_linter": {"keyword_suspicion"},
    "dependent_policy_full": {
        "purpose_field",
        "jurisdiction_field",
        "consent_field",
        "aggregation_threshold",
        "enhanced_audit",
        "compound",
    },
    "dependent_without_consent": {
        "purpose_field",
        "jurisdiction_field",
        "aggregation_threshold",
        "enhanced_audit",
    },
    "dependent_without_threshold": {
        "purpose_field",
        "jurisdiction_field",
        "consent_field",
        "enhanced_audit",
        "compound",
    },
    "dependent_without_enhanced_audit": {
        "purpose_field",
        "jurisdiction_field",
        "consent_field",
        "aggregation_threshold",
        "compound",
    },
    "dependent_without_purpose_field": {
        "jurisdiction_field",
        "consent_field",
        "aggregation_threshold",
        "enhanced_audit",
        "compound",
    },
    "dependent_without_jurisdiction_field": {
        "purpose_field",
        "consent_field",
        "aggregation_threshold",
        "enhanced_audit",
    },
}


FAMILY_CAPABILITY = {
    "purpose_conditioned_field": "purpose_field",
    "jurisdiction_conditioned_field": "jurisdiction_field",
    "consent_gated_field": "consent_field",
    "aggregation_threshold_leak": "aggregation_threshold",
    "emergency_audit_omission": "enhanced_audit",
    "compound_consent_purpose_scope": "compound",
}


DOMAINS = [
    {
        "domain": "benefits",
        "endpoint": "GET /benefits/{case_id}",
        "role": "case_worker",
        "valid_purpose": "appeal_review",
        "protected_field": "household_income",
        "base_risk": 9.0,
        "violations": {
            "purpose_conditioned_field": 14,
            "jurisdiction_conditioned_field": 8,
            "consent_gated_field": 16,
            "aggregation_threshold_leak": 6,
            "emergency_audit_omission": 6,
            "compound_consent_purpose_scope": 10,
        },
        "benign": {"authorized_detail": 18, "small_cell_suppressed": 8, "emergency_audited": 6, "cross_jurisdiction_redacted": 8},
    },
    {
        "domain": "health",
        "endpoint": "GET /patients/{person_id}/summary",
        "role": "clinician",
        "valid_purpose": "treatment",
        "protected_field": "diagnosis_detail",
        "base_risk": 10.0,
        "violations": {
            "purpose_conditioned_field": 8,
            "jurisdiction_conditioned_field": 6,
            "consent_gated_field": 18,
            "aggregation_threshold_leak": 5,
            "emergency_audit_omission": 17,
            "compound_consent_purpose_scope": 16,
        },
        "benign": {"authorized_detail": 20, "small_cell_suppressed": 6, "emergency_audited": 14, "cross_jurisdiction_redacted": 5},
    },
    {
        "domain": "education",
        "endpoint": "GET /students/{student_id}/record",
        "role": "school_admin",
        "valid_purpose": "student_support",
        "protected_field": "disciplinary_record",
        "base_risk": 8.0,
        "violations": {
            "purpose_conditioned_field": 14,
            "jurisdiction_conditioned_field": 9,
            "consent_gated_field": 9,
            "aggregation_threshold_leak": 8,
            "emergency_audit_omission": 4,
            "compound_consent_purpose_scope": 8,
        },
        "benign": {"authorized_detail": 16, "small_cell_suppressed": 8, "emergency_audited": 3, "cross_jurisdiction_redacted": 7},
    },
    {
        "domain": "licensing",
        "endpoint": "GET /licenses/{license_id}",
        "role": "licensing_officer",
        "valid_purpose": "license_review",
        "protected_field": "owner_identifier",
        "base_risk": 7.0,
        "violations": {
            "purpose_conditioned_field": 10,
            "jurisdiction_conditioned_field": 16,
            "consent_gated_field": 5,
            "aggregation_threshold_leak": 4,
            "emergency_audit_omission": 2,
            "compound_consent_purpose_scope": 9,
        },
        "benign": {"authorized_detail": 17, "small_cell_suppressed": 4, "emergency_audited": 2, "cross_jurisdiction_redacted": 12},
    },
    {
        "domain": "housing",
        "endpoint": "GET /housing/applications/{id}",
        "role": "housing_officer",
        "valid_purpose": "eligibility_review",
        "protected_field": "vulnerability_marker",
        "base_risk": 9.0,
        "violations": {
            "purpose_conditioned_field": 9,
            "jurisdiction_conditioned_field": 13,
            "consent_gated_field": 14,
            "aggregation_threshold_leak": 7,
            "emergency_audit_omission": 4,
            "compound_consent_purpose_scope": 13,
        },
        "benign": {"authorized_detail": 18, "small_cell_suppressed": 7, "emergency_audited": 4, "cross_jurisdiction_redacted": 10},
    },
    {
        "domain": "citizen_service",
        "endpoint": "GET /citizen-services/{request_id}",
        "role": "service_agent",
        "valid_purpose": "case_resolution",
        "protected_field": "family_linkage",
        "base_risk": 8.0,
        "violations": {
            "purpose_conditioned_field": 7,
            "jurisdiction_conditioned_field": 10,
            "consent_gated_field": 15,
            "aggregation_threshold_leak": 9,
            "emergency_audit_omission": 5,
            "compound_consent_purpose_scope": 10,
        },
        "benign": {"authorized_detail": 19, "small_cell_suppressed": 9, "emergency_audited": 4, "cross_jurisdiction_redacted": 9},
    },
]


def stable_score(*parts: object) -> float:
    payload = "|".join(str(part) for part in parts).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return int(digest[:12], 16) / float(0xFFFFFFFFFFFF)


def variant_fields(replica: int, protected_field: str, *fields: str) -> tuple[str, ...]:
    extras = ["status", "case_stage", "source_agency", "last_update", "review_flag"]
    selected = [field for field in fields if field]
    if replica % 2 == 0 and "status" not in selected:
        selected.insert(1 if selected else 0, "status")
    if replica % 3 == 0:
        selected.append(extras[replica % len(extras)])
    if protected_field in selected:
        selected = [field for index, field in enumerate(selected) if field not in selected[:index]]
    return tuple(selected)


def make_family_scenario(
    *,
    profile: dict,
    domain_index: int,
    replica: int,
    family: str,
    expected_violation: bool = True,
) -> Scenario:
    domain = profile["domain"]
    endpoint = f"{profile['endpoint']}/r{replica:03d}"
    role = profile["role"]
    valid_purpose = profile["valid_purpose"]
    protected_field = profile["protected_field"]
    base_risk = profile["base_risk"]
    common = {
        "replica": replica,
        "domain": domain,
        "endpoint": endpoint,
        "role": role,
        "field_family": protected_field,
    }
    group_size = 3 + ((replica + domain_index) % 5)
    if family == "purpose_conditioned_field":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_purpose_violation",
            purpose="routine_lookup",
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=24 + (replica % 11),
            returned_fields=variant_fields(replica, protected_field, "id", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="suppress purpose-restricted field",
            risk=round(base_risk * (6.5 + 0.2 * (replica % 4)), 2),
            **common,
        )
    if family == "jurisdiction_conditioned_field":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_jurisdiction_violation",
            purpose=valid_purpose,
            same_jurisdiction=False,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=22 + (replica % 13),
            returned_fields=variant_fields(replica, protected_field, "id", "precise_address", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="coarsen cross-jurisdiction response",
            risk=round(base_risk * (7.5 + 0.15 * (replica % 5)), 2),
            **common,
        )
    if family == "consent_gated_field":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_consent_violation",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=False,
            consent_scope_valid=False,
            emergency=False,
            group_size=25 + (replica % 10),
            returned_fields=variant_fields(replica, protected_field, "id", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="suppress consent-gated field",
            risk=round(base_risk * (8.2 + 0.25 * (replica % 4)), 2),
            **common,
        )
    if family == "aggregation_threshold_leak":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_threshold_violation",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=group_size,
            returned_fields=variant_fields(replica, protected_field, "group_count", protected_field),
            aggregate_returned=True,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="suppress small-cell aggregate",
            risk=round(base_risk * (5.0 + 0.35 * (8 - group_size)), 2),
            **common,
        )
    if family == "emergency_audit_omission":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_emergency_audit_violation",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=True,
            group_size=26 + (replica % 9),
            returned_fields=variant_fields(replica, protected_field, "id", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="emit enhanced emergency audit marker",
            risk=round(base_risk * (4.8 + 0.3 * (replica % 3)), 2),
            **common,
        )
    if family == "compound_consent_purpose_scope":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_compound_violation",
            purpose="routine_lookup",
            same_jurisdiction=False,
            object_relation=True,
            consent_active=False,
            consent_scope_valid=False,
            emergency=False,
            group_size=group_size,
            returned_fields=variant_fields(replica, protected_field, "id", "precise_address", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=True,
            expected_behavior="apply consent, purpose, and jurisdiction restrictions jointly",
            risk=round(base_risk * (10.0 + 0.4 * (replica % 5)), 2),
            **common,
        )
    if family == "benign_authorized_detail":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_benign_authorized_detail",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=30 + (replica % 17),
            returned_fields=variant_fields(replica, protected_field, "id", protected_field),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=False,
            expected_behavior="allow scoped disclosure",
            risk=0.0,
            **common,
        )
    if family == "benign_small_cell_suppressed":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_benign_small_cell_suppressed",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=group_size,
            returned_fields=("suppression_marker",),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=False,
            expected_behavior="suppress small-cell aggregate",
            risk=0.0,
            **common,
        )
    if family == "benign_emergency_audited":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_benign_emergency_audited",
            purpose=valid_purpose,
            same_jurisdiction=True,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=True,
            group_size=27 + (replica % 11),
            returned_fields=variant_fields(replica, protected_field, "id", protected_field),
            aggregate_returned=False,
            audit_marker="enhanced_emergency",
            violation_family=family,
            expected_violation=False,
            expected_behavior="allow emergency access with enhanced audit",
            risk=0.0,
            **common,
        )
    if family == "benign_cross_jurisdiction_redacted":
        return Scenario(
            scenario_id=f"{domain}_{replica:03d}_{domain_index}_benign_cross_jurisdiction_redacted",
            purpose=valid_purpose,
            same_jurisdiction=False,
            object_relation=True,
            consent_active=True,
            consent_scope_valid=True,
            emergency=False,
            group_size=25 + (replica % 14),
            returned_fields=variant_fields(replica, protected_field, "id", "coarse_area"),
            aggregate_returned=False,
            audit_marker="standard",
            violation_family=family,
            expected_violation=False,
            expected_behavior="coarsen cross-jurisdiction response",
            risk=0.0,
            **common,
        )
    raise ValueError(f"unknown family: {family}")


def make_scenarios(replicas: int) -> list[Scenario]:
    rows: list[Scenario] = []
    scale = max(1, round(replicas / 10))
    for domain_index, profile in enumerate(DOMAINS, start=1):
        for family, count in profile["violations"].items():
            for replica in range(count * scale):
                rows.append(make_family_scenario(profile=profile, domain_index=domain_index, replica=replica, family=family))
        for family_suffix, count in profile["benign"].items():
            family = f"benign_{family_suffix}"
            for replica in range(count * scale):
                rows.append(make_family_scenario(profile=profile, domain_index=domain_index, replica=replica, family=family, expected_violation=False))
    return rows


def method_detects(method: str, scenario: Scenario) -> bool:
    capabilities = METHOD_CAPABILITIES[method]
    score = stable_score(method, scenario.scenario_id)
    if "risk_heuristic" in capabilities:
        if scenario.expected_violation:
            threshold = {
                "compound_consent_purpose_scope": 0.88,
                "consent_gated_field": 0.80,
                "jurisdiction_conditioned_field": 0.72,
                "purpose_conditioned_field": 0.70,
                "aggregation_threshold_leak": 0.66,
                "emergency_audit_omission": 0.58,
            }[scenario.violation_family]
            return score < threshold
        benign_threshold = {
            "benign_authorized_detail": 0.18,
            "benign_small_cell_suppressed": 0.34,
            "benign_emergency_audited": 0.46,
            "benign_cross_jurisdiction_redacted": 0.52,
        }[scenario.violation_family]
        return score < benign_threshold
    if "keyword_suspicion" in capabilities:
        suspicious = (
            scenario.field_family in scenario.returned_fields
            or scenario.emergency
            or scenario.group_size < 8
            or not scenario.same_jurisdiction
            or not scenario.consent_active
        )
        threshold = 0.94 if scenario.expected_violation else 0.72
        return suspicious and score < threshold
    if not scenario.expected_violation:
        return False
    if scenario.violation_family == "compound_consent_purpose_scope":
        if "compound" in capabilities:
            return True
        if method == "pairwise_dependency_suite":
            return score < 0.46
        return (
            "consent_field" in capabilities and "purpose_field" in capabilities and "jurisdiction_field" in capabilities
        )
    return FAMILY_CAPABILITY[scenario.violation_family] in capabilities


def scenario_to_json(row: Scenario) -> dict:
    data = asdict(row)
    data["returned_fields"] = list(row.returned_fields)
    return data


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def summarize(judgments: list[dict]) -> list[dict]:
    out = []
    for method in sorted({row["method"] for row in judgments}):
        items = [row for row in judgments if row["method"] == method]
        tp = sum(1 for row in items if row["expected_violation"] and row["detected"])
        fp = sum(1 for row in items if not row["expected_violation"] and row["detected"])
        tn = sum(1 for row in items if not row["expected_violation"] and not row["detected"])
        fn = sum(1 for row in items if row["expected_violation"] and not row["detected"])
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        risk_total = sum(row["risk"] for row in items if row["expected_violation"])
        risk_detected = sum(row["risk"] for row in items if row["expected_violation"] and row["detected"])
        out.append({
            "method": method,
            "n": len(items),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1": round(f1, 4),
            "risk_weighted_recall": round(risk_detected / risk_total, 4) if risk_total else 0.0,
        })
    return out


def recall_by_family(judgments: list[dict]) -> list[dict]:
    out = []
    families = sorted({row["violation_family"] for row in judgments if row["expected_violation"]})
    for method in sorted({row["method"] for row in judgments}):
        for family in families:
            items = [row for row in judgments if row["method"] == method and row["violation_family"] == family]
            detected = sum(1 for row in items if row["detected"])
            risk_total = sum(row["risk"] for row in items)
            risk_detected = sum(row["risk"] for row in items if row["detected"])
            out.append({
                "method": method,
                "violation_family": family,
                "n": len(items),
                "detected": detected,
                "recall": round(detected / len(items), 4) if items else 0.0,
                "risk_weighted_recall": round(risk_detected / risk_total, 4) if risk_total else 0.0,
            })
    return out


def benign_false_alarm(judgments: list[dict]) -> list[dict]:
    out = []
    families = sorted({row["violation_family"] for row in judgments if not row["expected_violation"]})
    for method in sorted({row["method"] for row in judgments}):
        for family in families:
            items = [row for row in judgments if row["method"] == method and row["violation_family"] == family]
            fp = sum(1 for row in items if row["detected"])
            out.append({
                "method": method,
                "benign_family": family,
                "n": len(items),
                "false_positives": fp,
                "false_alarm_rate": round(fp / len(items), 4) if items else 0.0,
            })
    return out


def domain_summary(judgments: list[dict]) -> list[dict]:
    out = []
    for method in sorted({row["method"] for row in judgments}):
        for domain in sorted({row["domain"] for row in judgments}):
            items = [row for row in judgments if row["method"] == method and row["domain"] == domain]
            positives = [row for row in items if row["expected_violation"]]
            tp = sum(1 for row in positives if row["detected"])
            out.append({
                "method": method,
                "domain": domain,
                "n": len(items),
                "violations": len(positives),
                "detected": tp,
                "recall": round(tp / len(positives), 4) if positives else 0.0,
            })
    return out


def ablation_loss(summary: list[dict]) -> list[dict]:
    full = next(row for row in summary if row["method"] == "dependent_policy_full")
    rows = []
    for row in summary:
        if row["method"].startswith("dependent_without_"):
            rows.append({
                "ablation": row["method"].replace("dependent_without_", ""),
                "recall_loss": round(full["recall"] - row["recall"], 4),
                "risk_weighted_recall_loss": round(full["risk_weighted_recall"] - row["risk_weighted_recall"], 4),
                "f1_loss": round(full["f1"] - row["f1"], 4),
            })
    return sorted(rows, key=lambda item: item["risk_weighted_recall_loss"], reverse=True)


def metric_row(items: list[dict], risk_multipliers: dict[str, float] | None = None) -> dict:
    risk_multipliers = risk_multipliers or {}
    tp = sum(1 for row in items if row["expected_violation"] and row["detected"])
    fp = sum(1 for row in items if not row["expected_violation"] and row["detected"])
    tn = sum(1 for row in items if not row["expected_violation"] and not row["detected"])
    fn = sum(1 for row in items if row["expected_violation"] and not row["detected"])
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    specificity = tn / (tn + fp) if tn + fp else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    risk_total = 0.0
    risk_detected = 0.0
    for row in items:
        if not row["expected_violation"]:
            continue
        adjusted = row["risk"] * risk_multipliers.get(row["violation_family"], 1.0)
        risk_total += adjusted
        if row["detected"]:
            risk_detected += adjusted
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
        "risk_weighted_recall": risk_detected / risk_total if risk_total else 0.0,
    }


def bootstrap_intervals(judgments: list[dict], iterations: int = 1000) -> list[dict]:
    rng = random.Random(202607)
    selected = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
    ]
    scenario_ids = sorted({row["scenario_id"] for row in judgments})
    by_scenario = {
        scenario_id: [row for row in judgments if row["scenario_id"] == scenario_id and row["method"] in selected]
        for scenario_id in scenario_ids
    }
    distributions: dict[tuple[str, str], list[float]] = {
        (method, metric): [] for method in selected for metric in ["recall", "specificity", "f1", "risk_weighted_recall"]
    }
    for _ in range(iterations):
        sampled = [rng.choice(scenario_ids) for _ in scenario_ids]
        sample_rows = [row for scenario_id in sampled for row in by_scenario[scenario_id]]
        for method in selected:
            metrics = metric_row([row for row in sample_rows if row["method"] == method])
            for metric in ["recall", "specificity", "f1", "risk_weighted_recall"]:
                distributions[(method, metric)].append(metrics[metric])
    out = []
    for method in selected:
        point = metric_row([row for row in judgments if row["method"] == method])
        for metric in ["recall", "specificity", "f1", "risk_weighted_recall"]:
            values = sorted(distributions[(method, metric)])
            out.append({
                "method": method,
                "metric": metric,
                "point": round(point[metric], 4),
                "ci_low": round(values[int(0.025 * iterations)], 4),
                "ci_high": round(values[int(0.975 * iterations) - 1], 4),
            })
    return out


def weight_sensitivity(judgments: list[dict]) -> list[dict]:
    schemes = {
        "baseline": {},
        "equal_family": {
            "aggregation_threshold_leak": 0.0,
            "compound_consent_purpose_scope": 0.0,
            "consent_gated_field": 0.0,
            "emergency_audit_omission": 0.0,
            "jurisdiction_conditioned_field": 0.0,
            "purpose_conditioned_field": 0.0,
        },
        "consent_heavy": {"consent_gated_field": 1.8, "compound_consent_purpose_scope": 1.4},
        "jurisdiction_heavy": {"jurisdiction_conditioned_field": 1.8, "compound_consent_purpose_scope": 1.3},
        "audit_heavy": {"emergency_audit_omission": 2.0},
        "threshold_heavy": {"aggregation_threshold_leak": 2.0},
    }
    methods = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
        "dependent_without_threshold",
        "dependent_without_enhanced_audit",
    ]
    rows = []
    families = sorted({row["violation_family"] for row in judgments if row["expected_violation"]})
    family_average = {}
    for family in families:
        values = [row["risk"] for row in judgments if row["method"] == "dependent_policy_full" and row["violation_family"] == family]
        family_average[family] = sum(values) / len(values)
    for scheme, multipliers in schemes.items():
        if scheme == "equal_family":
            normalized = {family: 1.0 / family_average[family] for family in families}
        else:
            normalized = multipliers
        for method in methods:
            metrics = metric_row([row for row in judgments if row["method"] == method], normalized)
            rows.append({
                "scheme": scheme,
                "method": method,
                "risk_weighted_recall": round(metrics["risk_weighted_recall"], 4),
            })
    return rows


def unknown_clause_sensitivity(judgments: list[dict]) -> list[dict]:
    methods = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
    ]
    unknown_loads = [0.0, 0.05, 0.10, 0.20, 0.30]
    rows = []
    known_total = sum(row["risk"] for row in judgments if row["method"] == "dependent_policy_full" and row["expected_violation"])
    for method in methods:
        known_detected = sum(row["risk"] for row in judgments if row["method"] == method and row["expected_violation"] and row["detected"])
        for unknown_load in unknown_loads:
            unknown_risk = known_total * unknown_load
            adjusted_recall = known_detected / (known_total + unknown_risk)
            rows.append({
                "unknown_risk_load": unknown_load,
                "method": method,
                "adjusted_risk_weighted_recall": round(adjusted_recall, 4),
                "escaped_risk_share": round(1 - adjusted_recall, 4),
            })
    return rows


def workload_by_prevalence(summary: list[dict]) -> list[dict]:
    methods = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
        "basic_policy_aware_full",
    ]
    prevalences = [0.01, 0.05, 0.10, 0.20]
    lookup = {row["method"]: row for row in summary}
    rows = []
    for method in methods:
        recall = lookup[method]["recall"]
        false_positive_rate = 1 - lookup[method]["specificity"]
        for prevalence in prevalences:
            alerts = prevalence * recall + (1 - prevalence) * false_positive_rate
            ppv = (prevalence * recall / alerts) if alerts else 0.0
            rows.append({
                "method": method,
                "violation_prevalence": prevalence,
                "alerts_per_10000_changes": round(alerts * 10000, 1),
                "expected_true_alerts": round(prevalence * recall * 10000, 1),
                "expected_false_alerts": round((1 - prevalence) * false_positive_rate * 10000, 1),
                "positive_predictive_value": round(ppv, 4),
            })
    return rows


def escape_cases(judgments: list[dict]) -> list[dict]:
    selected = [
        "pairwise_dependency_suite",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
        "dependent_without_purpose_field",
        "dependent_without_threshold",
        "dependent_without_enhanced_audit",
    ]
    rows = []
    for method in selected:
        misses = [
            row for row in judgments
            if row["method"] == method and row["expected_violation"] and not row["detected"]
        ]
        for row in sorted(misses, key=lambda item: item["risk"], reverse=True)[:5]:
            rows.append({
                "method": method,
                "scenario_id": row["scenario_id"],
                "domain": row["domain"],
                "violation_family": row["violation_family"],
                "risk": row["risk"],
                "expected_behavior": row["expected_behavior"],
            })
    return rows


def suite_growth_table(scenarios: list[Scenario]) -> list[dict]:
    dimensions = {
        "roles": len({row.role for row in scenarios}),
        "purposes": len({row.purpose for row in scenarios}),
        "field_families": len({row.field_family for row in scenarios}),
        "jurisdiction_states": 2,
        "consent_states": 2,
        "aggregation_classes": 2,
        "audit_contexts": 2,
    }
    exhaustive = 1
    for value in dimensions.values():
        exhaustive *= value
    return [
        {
            "strategy": "Independent checklist",
            "unit_count": 6,
            "interpretation": "One surface each for schema, role, object, field, audit, and inventory",
        },
        {
            "strategy": "Behavior-changing clause families",
            "unit_count": len(FAMILY_CAPABILITY),
            "interpretation": "Purpose, consent, jurisdiction, threshold, emergency audit, and compound clauses",
        },
        {
            "strategy": "Generated benchmark scenarios",
            "unit_count": len(scenarios),
            "interpretation": "Negative cases and paired benign controls used in the study",
        },
        {
            "strategy": "Naive cross-product contexts",
            "unit_count": exhaustive,
            "interpretation": "Cartesian product of observed roles, purposes, fields, jurisdiction, consent, aggregation, and audit states",
        },
    ]


def make_figures(
    summary: list[dict],
    losses: list[dict],
    family_rows: list[dict],
    judgments: list[dict],
    bootstrap_rows: list[dict],
    weight_rows: list[dict],
    unknown_rows: list[dict],
    workload_rows: list[dict],
) -> None:
    try:
        import matplotlib.pyplot as plt
    except Exception:
        return
    FIGURES_DIR.mkdir(parents=True, exist_ok=True)

    selected = [
        "schema_validation",
        "basic_policy_aware_full",
        "keyword_sensitive_privacy_linter",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_threshold",
        "dependent_without_enhanced_audit",
        "dependent_without_purpose_field",
        "dependent_without_jurisdiction_field",
    ]
    lookup = {row["method"]: row for row in summary}
    labels = [name.replace("_", "\n") for name in selected]
    recall = [lookup[name]["recall"] for name in selected]
    specificity = [lookup[name]["specificity"] for name in selected]
    fig, ax = plt.subplots(figsize=(9, 4.5))
    x = range(len(selected))
    ax.bar([i - 0.18 for i in x], recall, width=0.36, label="Recall")
    ax.bar([i + 0.18 for i in x], specificity, width=0.36, label="Specificity")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Score")
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=7)
    ax.legend(frameon=False)
    ax.set_title("Dependent-policy detection trade-off")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "method_recall_specificity.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7, 3.8))
    labels = [row["ablation"].replace("_", "\n") for row in losses]
    values = [row["risk_weighted_recall_loss"] for row in losses]
    ax.bar(labels, values, color="#5b6f95")
    ax.set_ylim(0, max(values) + 0.08)
    ax.set_ylabel("Risk-weighted recall loss")
    ax.set_title("Coverage loss by removed interaction clause")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "ablation_risk_loss.pdf")
    plt.close(fig)

    heat_methods = [
        "basic_policy_aware_full",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_threshold",
        "dependent_without_enhanced_audit",
        "dependent_without_purpose_field",
        "dependent_without_jurisdiction_field",
    ]
    families = sorted({row["violation_family"] for row in family_rows})
    matrix = []
    for method in heat_methods:
        matrix.append([
            next(row["recall"] for row in family_rows if row["method"] == method and row["violation_family"] == family)
            for family in families
        ])
    fig, ax = plt.subplots(figsize=(8.5, 4.2))
    image = ax.imshow(matrix, vmin=0, vmax=1, cmap="viridis")
    ax.set_xticks(range(len(families)))
    ax.set_xticklabels([f.replace("_", "\n") for f in families], rotation=45, ha="right", fontsize=7)
    ax.set_yticks(range(len(heat_methods)))
    ax.set_yticklabels([m.replace("_", " ") for m in heat_methods], fontsize=7)
    ax.set_title("Recall by dependent violation family")
    fig.colorbar(image, ax=ax, fraction=0.035, pad=0.02)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "family_recall_heatmap.pdf")
    plt.close(fig)

    domains = sorted({row["domain"] for row in judgments})
    violation_counts = []
    benign_counts = []
    for domain in domains:
        domain_rows = [row for row in judgments if row["domain"] == domain and row["method"] == "dependent_policy_full"]
        violation_counts.append(sum(1 for row in domain_rows if row["expected_violation"]))
        benign_counts.append(sum(1 for row in domain_rows if not row["expected_violation"]))
    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    x = range(len(domains))
    ax.bar(x, violation_counts, label="Dependent violations", color="#6a7fb0")
    ax.bar(x, benign_counts, bottom=violation_counts, label="Benign controls", color="#d2a85c")
    ax.set_xticks(list(x))
    ax.set_xticklabels([d.replace("_", "\n") for d in domains], fontsize=8)
    ax.set_ylabel("Scenarios")
    ax.set_title("Benchmark composition by public-service domain")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "benchmark_domain_composition.pdf")
    plt.close(fig)

    selected_false_alarm = [
        "schema_validation",
        "basic_policy_aware_full",
        "keyword_sensitive_privacy_linter",
        "dependent_policy_full",
    ]
    benign_families = sorted({row["violation_family"] for row in judgments if not row["expected_violation"]})
    false_alarm_matrix = []
    for method in selected_false_alarm:
        row_values = []
        for family in benign_families:
            items = [
                row for row in judgments
                if row["method"] == method and row["violation_family"] == family and not row["expected_violation"]
            ]
            row_values.append(sum(1 for row in items if row["detected"]) / len(items))
        false_alarm_matrix.append(row_values)
    fig, ax = plt.subplots(figsize=(7.8, 3.8))
    image = ax.imshow(false_alarm_matrix, vmin=0, vmax=1, cmap="magma_r")
    ax.set_xticks(range(len(benign_families)))
    ax.set_xticklabels([f.replace("benign_", "").replace("_", "\n") for f in benign_families], fontsize=8)
    ax.set_yticks(range(len(selected_false_alarm)))
    ax.set_yticklabels([m.replace("_", " ") for m in selected_false_alarm], fontsize=8)
    ax.set_title("False-alarm rate on benign dependent-policy controls")
    fig.colorbar(image, ax=ax, fraction=0.04, pad=0.02)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "benign_false_alarm_heatmap.pdf")
    plt.close(fig)

    selected_domain_methods = [
        "basic_policy_aware_full",
        "aggregation_only_tests",
        "keyword_sensitive_privacy_linter",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
        "dependent_without_threshold",
    ]
    matrix = []
    for method in selected_domain_methods:
        row_values = []
        for domain in domains:
            items = [
                row for row in judgments
                if row["method"] == method and row["domain"] == domain and row["expected_violation"]
            ]
            row_values.append(sum(1 for row in items if row["detected"]) / len(items))
        matrix.append(row_values)
    fig, ax = plt.subplots(figsize=(8.4, 4.0))
    image = ax.imshow(matrix, vmin=0, vmax=1, cmap="cividis")
    ax.set_xticks(range(len(domains)))
    ax.set_xticklabels([d.replace("_", "\n") for d in domains], fontsize=8)
    ax.set_yticks(range(len(selected_domain_methods)))
    ax.set_yticklabels([m.replace("_", " ") for m in selected_domain_methods], fontsize=7)
    ax.set_title("Violation recall by method and service domain")
    fig.colorbar(image, ax=ax, fraction=0.04, pad=0.02)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "domain_recall_heatmap.pdf")
    plt.close(fig)

    risk_by_family = []
    for family in families:
        total = sum(
            row["risk"] for row in judgments
            if row["method"] == "dependent_policy_full" and row["violation_family"] == family
        )
        risk_by_family.append(total)
    fig, ax = plt.subplots(figsize=(8.0, 3.8))
    ax.bar([f.replace("_", "\n") for f in families], risk_by_family, color="#7b6d9a")
    ax.set_ylabel("Total synthetic risk weight")
    ax.set_title("Risk-weight mass by dependent violation family")
    ax.tick_params(axis="x", labelsize=7)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "risk_weight_by_family.pdf")
    plt.close(fig)

    ci_methods = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
    ]
    ci_items = [row for row in bootstrap_rows if row["metric"] == "risk_weighted_recall" and row["method"] in ci_methods]
    fig, ax = plt.subplots(figsize=(8.6, 3.8))
    points = [row["point"] for row in ci_items]
    lows = [row["point"] - row["ci_low"] for row in ci_items]
    highs = [row["ci_high"] - row["point"] for row in ci_items]
    ci_x = range(len(ci_items))
    ax.errorbar(ci_x, points, yerr=[lows, highs], fmt="o", capsize=4, color="#4f6d7a")
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Risk-weighted recall")
    ax.set_xticks(list(ci_x))
    ax.set_xticklabels([row["method"].replace("_", "\n") for row in ci_items], rotation=45, ha="right", fontsize=7)
    ax.set_title("Bootstrap intervals for risk-weighted recall")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "bootstrap_rwr_intervals.pdf")
    plt.close(fig)

    sens_methods = [
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
        "dependent_policy_full",
    ]
    schemes = ["baseline", "equal_family", "consent_heavy", "jurisdiction_heavy", "audit_heavy", "threshold_heavy"]
    fig, ax = plt.subplots(figsize=(8.6, 4.2))
    for method in sens_methods:
        values = [
            next(row["risk_weighted_recall"] for row in weight_rows if row["method"] == method and row["scheme"] == scheme)
            for scheme in schemes
        ]
        ax.plot(schemes, values, marker="o", linewidth=1.6, label=method.replace("_", " "))
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Risk-weighted recall")
    ax.set_title("Sensitivity to severity-weight schemes")
    ax.tick_params(axis="x", labelrotation=25, labelsize=8)
    ax.legend(frameon=False, fontsize=6, ncol=2)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "weight_sensitivity.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(7.6, 3.8))
    for method in ["risk_heuristic_privacy_linter", "keyword_sensitive_privacy_linter", "pairwise_dependency_suite", "dependent_policy_full"]:
        items = [row for row in unknown_rows if row["method"] == method]
        ax.plot(
            [row["unknown_risk_load"] for row in items],
            [row["adjusted_risk_weighted_recall"] for row in items],
            marker="o",
            label=method.replace("_", " "),
        )
    ax.set_ylim(0, 1.05)
    ax.set_xlabel("Unknown-clause risk load relative to represented risk")
    ax.set_ylabel("Adjusted risk-weighted recall")
    ax.set_title("Sensitivity to unrepresented dependent clauses")
    ax.legend(frameon=False, fontsize=7)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "unknown_clause_sensitivity.pdf")
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(8.0, 4.0))
    for method in ["risk_heuristic_privacy_linter", "keyword_sensitive_privacy_linter", "pairwise_dependency_suite", "dependent_policy_full"]:
        items = [row for row in workload_rows if row["method"] == method]
        ax.plot(
            [100 * row["violation_prevalence"] for row in items],
            [row["alerts_per_10000_changes"] for row in items],
            marker="o",
            label=method.replace("_", " "),
        )
    ax.set_xlabel("Assumed violation prevalence (%)")
    ax.set_ylabel("Alerts per 10,000 changes")
    ax.set_title("Expected review workload under prevalence assumptions")
    ax.legend(frameon=False, fontsize=7)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "prevalence_workload.pdf")
    plt.close(fig)

    fig, axes = plt.subplots(2, 2, figsize=(10.5, 8.0))
    ax = axes[0, 0]
    overview_methods = [
        "basic_policy_aware_full",
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
    ]
    x = range(len(overview_methods))
    ax.bar([i - 0.18 for i in x], [lookup[m]["recall"] for m in overview_methods], width=0.36, label="Recall")
    ax.bar([i + 0.18 for i in x], [lookup[m]["specificity"] for m in overview_methods], width=0.36, label="Specificity")
    ax.set_ylim(0, 1.05)
    ax.set_title("(a) Detection trade-off")
    ax.set_xticks(list(x))
    ax.set_xticklabels(["basic", "risk\nlinter", "keyword\nlinter", "pairwise", "full"], fontsize=8)
    ax.legend(frameon=False, fontsize=8)

    ax = axes[0, 1]
    image = ax.imshow(false_alarm_matrix, vmin=0, vmax=1, cmap="magma_r")
    ax.set_title("(b) Benign false alarms")
    ax.set_xticks(range(len(benign_families)))
    ax.set_xticklabels([f.replace("benign_", "").replace("_", "\n") for f in benign_families], fontsize=7)
    ax.set_yticks(range(len(selected_false_alarm)))
    ax.set_yticklabels(["schema", "basic", "keyword", "full"], fontsize=8)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.02)

    ax = axes[1, 0]
    selected_domain_methods_short = [
        "basic_policy_aware_full",
        "risk_heuristic_privacy_linter",
        "keyword_sensitive_privacy_linter",
        "pairwise_dependency_suite",
        "dependent_policy_full",
        "dependent_without_consent",
        "dependent_without_jurisdiction_field",
    ]
    domain_matrix = []
    for method in selected_domain_methods_short:
        row_values = []
        for domain in domains:
            items = [
                row for row in judgments
                if row["method"] == method and row["domain"] == domain and row["expected_violation"]
            ]
            row_values.append(sum(1 for row in items if row["detected"]) / len(items))
        domain_matrix.append(row_values)
    image = ax.imshow(domain_matrix, vmin=0, vmax=1, cmap="cividis")
    ax.set_title("(c) Recall by domain")
    ax.set_xticks(range(len(domains)))
    ax.set_xticklabels([d.replace("_", "\n") for d in domains], fontsize=8)
    ax.set_yticks(range(len(selected_domain_methods_short)))
    ax.set_yticklabels(["basic", "risk", "keyword", "pairwise", "full", "-consent", "-juris"], fontsize=8)
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.02)

    ax = axes[1, 1]
    labels = [row["ablation"].replace("_", "\n") for row in losses]
    values = [row["risk_weighted_recall_loss"] for row in losses]
    ax.bar(labels, values, color="#5b6f95")
    ax.set_ylim(0, max(values) + 0.08)
    ax.set_title("(d) Ablation loss")
    ax.set_ylabel("Risk-weighted recall loss")
    ax.tick_params(axis="x", labelsize=8)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "result_profile_panels.pdf")
    plt.close(fig)

    fig, axes = plt.subplots(2, 2, figsize=(10.5, 8.0))
    ax = axes[0, 0]
    ci_x = range(len(ci_items))
    ax.errorbar(ci_x, points, yerr=[lows, highs], fmt="o", capsize=4, color="#4f6d7a")
    ax.set_ylim(0, 1.05)
    ax.set_title("(a) Bootstrap risk-weighted recall")
    ax.set_xticks(list(ci_x))
    ax.set_xticklabels(["risk", "keyword", "pairwise", "full", "-consent", "-juris"], fontsize=8)

    ax = axes[0, 1]
    for method in ["pairwise_dependency_suite", "dependent_without_consent", "dependent_without_jurisdiction_field", "dependent_policy_full"]:
        values = [
            next(row["risk_weighted_recall"] for row in weight_rows if row["method"] == method and row["scheme"] == scheme)
            for scheme in schemes
        ]
        ax.plot(schemes, values, marker="o", linewidth=1.6, label=method.replace("dependent_", "").replace("_", " "))
    ax.set_ylim(0, 1.05)
    ax.set_title("(b) Severity-weight sensitivity")
    ax.tick_params(axis="x", labelrotation=25, labelsize=8)
    ax.legend(frameon=False, fontsize=7)

    ax = axes[1, 0]
    for method in ["risk_heuristic_privacy_linter", "keyword_sensitive_privacy_linter", "pairwise_dependency_suite", "dependent_policy_full"]:
        items = [row for row in unknown_rows if row["method"] == method]
        ax.plot(
            [row["unknown_risk_load"] for row in items],
            [row["adjusted_risk_weighted_recall"] for row in items],
            marker="o",
            label=method.replace("_", " "),
        )
    ax.set_ylim(0, 1.05)
    ax.set_title("(c) Unknown-clause sensitivity")
    ax.set_xlabel("Unknown risk load")
    ax.set_ylabel("Adjusted RWR")
    ax.legend(frameon=False, fontsize=7)

    ax = axes[1, 1]
    for method in ["risk_heuristic_privacy_linter", "keyword_sensitive_privacy_linter", "pairwise_dependency_suite", "dependent_policy_full"]:
        items = [row for row in workload_rows if row["method"] == method]
        ax.plot(
            [100 * row["violation_prevalence"] for row in items],
            [row["alerts_per_10000_changes"] for row in items],
            marker="o",
            label=method.replace("_", " "),
        )
    ax.set_title("(d) Review workload")
    ax.set_xlabel("Violation prevalence (%)")
    ax.set_ylabel("Alerts per 10,000")
    ax.legend(frameon=False, fontsize=7)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "robustness_profile_panels.pdf")
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--replicas", type=int, default=10)
    args = parser.parse_args()

    scenarios = make_scenarios(args.replicas)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    write_jsonl(DATA_DIR / "dependent_policy_scenarios.jsonl", [scenario_to_json(row) for row in scenarios])

    judgments = []
    for scenario in scenarios:
        for method in METHOD_CAPABILITIES:
            judgments.append({
                "scenario_id": scenario.scenario_id,
                "domain": scenario.domain,
                "violation_family": scenario.violation_family,
                "method": method,
                "expected_violation": scenario.expected_violation,
                "detected": method_detects(method, scenario),
                "risk": scenario.risk,
                "expected_behavior": scenario.expected_behavior,
            })

    summary = summarize(judgments)
    family = recall_by_family(judgments)
    benign = benign_false_alarm(judgments)
    domains = domain_summary(judgments)
    losses = ablation_loss(summary)
    bootstrap = bootstrap_intervals(judgments)
    weights = weight_sensitivity(judgments)
    unknown = unknown_clause_sensitivity(judgments)
    workload = workload_by_prevalence(summary)
    escapes = escape_cases(judgments)
    growth = suite_growth_table(scenarios)

    write_csv(RESULTS_DIR / "method_summary.csv", summary)
    write_csv(RESULTS_DIR / "recall_by_violation_family.csv", family)
    write_csv(RESULTS_DIR / "benign_false_alarm.csv", benign)
    write_csv(RESULTS_DIR / "domain_summary.csv", domains)
    write_csv(RESULTS_DIR / "ablation_loss.csv", losses)
    write_csv(RESULTS_DIR / "bootstrap_intervals.csv", bootstrap)
    write_csv(RESULTS_DIR / "weight_sensitivity.csv", weights)
    write_csv(RESULTS_DIR / "unknown_clause_sensitivity.csv", unknown)
    write_csv(RESULTS_DIR / "prevalence_workload.csv", workload)
    write_csv(RESULTS_DIR / "escape_cases.csv", escapes)
    write_csv(RESULTS_DIR / "suite_growth.csv", growth)
    write_csv(RESULTS_DIR / "judgments.csv", judgments)
    write_csv(RESULTS_DIR / "casebook.csv", [scenario_to_json(row) for row in scenarios[:36]])
    (RESULTS_DIR / "experiment_summary.json").write_text(json.dumps({
        "replicas": args.replicas,
        "domains": len(DOMAINS),
        "scenarios": len(scenarios),
        "violations": sum(1 for row in scenarios if row.expected_violation),
        "benign_controls": sum(1 for row in scenarios if not row.expected_violation),
        "methods": len(METHOD_CAPABILITIES),
        "method_scenario_judgments": len(judgments),
        "violation_families": sorted(set(FAMILY_CAPABILITY)),
    }, indent=2), encoding="utf-8")
    make_figures(summary, losses, family, judgments, bootstrap, weights, unknown, workload)
    print(f"scenarios={len(scenarios)} judgments={len(judgments)}")
    print(f"wrote results to {RESULTS_DIR}")


if __name__ == "__main__":
    main()
