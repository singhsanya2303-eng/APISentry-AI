"""Train and evaluate the separate CSIC 2010 HTTP anomaly research classifier.

Research-only entry point::

    python -m scripts.train_csic_http_classifier \
        --zip-path ../research/datasets/raw/<archive>.zip \
        --expected-hash <sha256> \
        --output-dir models/csic_http_anomaly/v1

No model output from this script is consumed by runtime detection, mitigation,
authentication, or any enforcement path.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from app.services.csic_http_feature_adapter import (
    CsicHttpFeatureAdapter,
    analyze_split_overlap,
    create_group_split,
    dataset_provenance,
    load_records_from_zip,
    verify_dataset_hash,
)
from app.services.csic_training_service import (
    ACCEPTANCE_CRITERIA,
    build_models,
    check_acceptance,
    evaluate_all_models,
    fit_models,
    render_report,
    save_artifact,
    select_model,
    write_json_guard,
)


DEFAULT_ARCHIVE = (
    Path(__file__).resolve().parents[2]
    / "research"
    / "datasets"
    / "raw"
    / "output_http_csic_2010_weka_with_duplications_RAW-RFC2616_escd_v02_full.csv.zip"
)
DEFAULT_OUTPUT = Path(__file__).resolve().parents[1] / "models" / "csic_http_anomaly" / "v1"
DEFAULT_HASH = "46f207d266909bfd46cb255d8a357828cba9ee49a93d8ea7becf0354c7446a0e"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip-path", type=Path, default=DEFAULT_ARCHIVE)
    parser.add_argument("--expected-hash", default=DEFAULT_HASH)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--train-ratio", type=float, default=0.7)
    parser.add_argument("--validation-ratio", type=float, default=0.15)
    return parser


def _write_text_guard(path: Path, content: str) -> Path:
    if path.exists():
        raise FileExistsError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def run_training(args: argparse.Namespace) -> dict[str, object]:
    # 1. Integrity gate before any data processing.
    dataset_hash = verify_dataset_hash(args.zip_path, args.expected_hash)
    print(f"dataset_sha256_verified={dataset_hash}")

    records = load_records_from_zip(args.zip_path)
    print(f"rows={len(records)} sessions={len({record.session for record in records})}")

    output_dir = args.output_dir
    model_path = output_dir / "model.joblib"
    if model_path.exists():
        raise FileExistsError(f"refusing to overwrite existing artifact: {model_path}")

    # 2. Acceptance criteria are recorded before the test partition is touched.
    write_json_guard(output_dir / "acceptance_criteria.json", ACCEPTANCE_CRITERIA)
    print("acceptance_criteria_recorded=true")

    # 3. Group-aware split and leakage diagnostics.
    split = create_group_split(
        records,
        seed=args.seed,
        train_ratio=args.train_ratio,
        validation_ratio=args.validation_ratio,
    )
    overlap = analyze_split_overlap(records, split)
    provenance = dataset_provenance(args.zip_path, dataset_hash, records)
    for name, summary in split.summary["splits"].items():
        print(
            f"split={name} rows={summary['row_count']} "
            f"sessions={summary['session_count']} labels={summary['label_counts']}"
        )

    train_records = split.records_for(records, "train")
    validation_records = split.records_for(records, "validation")
    test_records = split.records_for(records, "test")

    # 4. Fit preprocessing on training rows only.
    adapter = CsicHttpFeatureAdapter(seed=args.seed)
    train_features = adapter.fit_transform(train_records)
    validation_features = adapter.transform(validation_records)
    test_features = adapter.transform(test_records)
    print(f"feature_schema={adapter.feature_schema_}")

    # 5. Train baselines and select on validation only.
    specifications = build_models(args.seed)
    fitted = fit_models(specifications, train_features)
    validation_results = evaluate_all_models(fitted, validation_features, validation_records)
    selected = select_model(validation_results)
    print(f"selected_model={selected}")

    # 6. Final held-out evaluation, performed only after model selection.
    test_results = evaluate_all_models(fitted, test_features, test_records)
    session_overlap_count = overlap["sessions_in_multiple_splits"]
    acceptance = check_acceptance(
        test_results[selected],
        test_results["deterministic_keyword_baseline"],
        session_overlap_count,
    )
    print(f"acceptance_passed={acceptance['passed']}")

    report: dict[str, object] = {
        "provenance": provenance,
        "dataset_sha256": dataset_hash,
        "split": split.summary,
        "session_isolation": {
            "sessions_in_multiple_splits": session_overlap_count,
            "feature_overlap": overlap,
        },
        "feature_schema": adapter.feature_schema_,
        "model_configurations": {
            name: {
                key: value
                for key, value in item["spec"].items()
                if key != "estimator"
            }
            for name, item in fitted.items()
        },
        "selected_model": selected,
        "validation_results": validation_results,
        "test_results": test_results,
        "acceptance": acceptance,
        "research_only": True,
    }

    artifact: dict[str, object] = {
        "artifact_version": 1,
        "research_only": True,
        "model_name": selected,
        "model": fitted[selected]["estimator"],
        "adapter": adapter,
        "feature_view": fitted[selected]["spec"]["feature_view"],
        "score_kind": fitted[selected]["spec"]["score_kind"],
        "threshold": fitted[selected]["spec"]["threshold"],
        "feature_schema": adapter.feature_schema_,
        "dataset_sha256": dataset_hash,
        "split_seed": args.seed,
        "split_summary": split.summary,
        "evaluation": {
            "validation": validation_results,
            "test": test_results,
            "acceptance": acceptance,
        },
        "limitations": provenance["limitations"],
    }

    saved_model = save_artifact(model_path, artifact)
    saved_json = write_json_guard(output_dir / "evaluation_report.json", report)
    saved_markdown = _write_text_guard(
        output_dir / "evaluation_report.md", render_report(report)
    )
    print(f"saved_model={saved_model}")
    print(f"saved_report_json={saved_json}")
    print(f"saved_report_markdown={saved_markdown}")
    return report


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_training(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
