"""
ChainForensics — Sprint 1: Attack Detection Model

Production-grade traffic classification: train, persist (versioned), load, and infer.

Design decisions:
    - RandomForestClassifier with class_weight="balanced" because attack classes
      are rare relative to benign traffic in real-world datasets (CICIDS2017 is
      ~80 % BENIGN).  Balanced weighting up-weights minority classes during
      training so the model does not learn to predict "BENIGN" for everything.
    - Model artifacts use versioned filenames (timestamp + UUID) so that a bad
      model can be rolled back to a previous known-good version without data
      loss.  A single overwritten file would make rollback impossible.
    - Training metadata (class distribution, duration, metrics) is appended to
      a structured JSONL log, not just printed to stdout, so that training
      history is auditable and machine-parseable for BASE evaluation later.
"""
from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from .exceptions import InferenceInputError, ModelArtifactError
from .features import FEATURE_COLUMNS, FeatureCleaner, split_features_and_labels

LOGGER = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────

SUPPORTED_CLASSES = ("BENIGN", "DoS", "PortScan", "BruteForce")
MODEL_SCHEMA_VERSION = 1


# ─── Typed data classes ─────────────────────────────────

@dataclass(frozen=True)
class Prediction:
    """Single-row inference result with label and per-class probabilities."""
    label: str
    probabilities: dict[str, float]


@dataclass(frozen=True)
class DetectorArtifact:
    """Everything needed to reproduce inference from a persisted model."""
    model: RandomForestClassifier
    cleaner: FeatureCleaner
    feature_columns: tuple[str, ...]
    model_version: str
    schema_version: int


# ─── Internal helpers ───────────────────────────────────

def _generate_version() -> str:
    """Unique, sortable version string: v<UTC timestamp>_<short UUID>."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    short_id = uuid.uuid4().hex[:10]
    return f"v{ts}_{short_id}"


# ─── Training ───────────────────────────────────────────

def train_and_persist(
    frame: pd.DataFrame,
    *,
    models_dir: str | Path = "models",
    logs_dir: str | Path = "logs",
    test_size: float = 0.2,
    random_state: int = 42,
) -> tuple[Path, dict]:
    """
    End-to-end training pipeline:
        raw DataFrame → feature split → clean → train → evaluate → persist.

    Returns (artifact_path, metadata_dict).
    """
    # ── Split features / labels ──
    features, labels = split_features_and_labels(frame)

    # Stratification check: requires >=2 samples per class, and test/train size >= n_classes
    class_counts = labels.value_counts()
    n_classes = len(class_counts)
    n_test_samples = int(round(len(labels) * test_size)) if isinstance(test_size, float) else int(test_size)
    n_train_samples = len(labels) - n_test_samples
    can_stratify = (
        class_counts.min() >= 2
        and n_test_samples >= n_classes
        and n_train_samples >= n_classes
    )

    X_train, X_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=test_size,
        random_state=random_state,
        stratify=labels if can_stratify else None,
    )

    # ── Clean features ──
    cleaner = FeatureCleaner()
    X_train_clean = cleaner.fit_transform(X_train)
    X_test_clean = cleaner.transform(X_test)

    # ── Train ──
    LOGGER.info(
        "training_start train_size=%d test_size=%d features=%d",
        len(X_train_clean),
        len(X_test_clean),
        len(FEATURE_COLUMNS),
    )

    start = perf_counter()

    model = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=random_state,
        n_jobs=-1,
    )
    model.fit(X_train_clean, y_train)

    duration = perf_counter() - start

    # ── Evaluate ──
    y_pred = model.predict(X_test_clean)

    report = classification_report(
        y_test,
        y_pred,
        labels=list(SUPPORTED_CLASSES),
        target_names=list(SUPPORTED_CLASSES),
        output_dict=True,
        zero_division=0,
    )

    LOGGER.info(
        "training_complete duration_seconds=%.4f accuracy=%.4f",
        duration,
        report.get("accuracy", 0.0),
    )

    # ── Persist artifact (versioned filename) ──
    version = _generate_version()

    artifact = DetectorArtifact(
        model=model,
        cleaner=cleaner,
        feature_columns=tuple(FEATURE_COLUMNS),
        model_version=version,
        schema_version=MODEL_SCHEMA_VERSION,
    )

    models_path = Path(models_dir)
    logs_path = Path(logs_dir)
    models_path.mkdir(parents=True, exist_ok=True)
    logs_path.mkdir(parents=True, exist_ok=True)

    artifact_file = models_path / f"detector_{version}.joblib"
    joblib.dump(artifact, artifact_file)

    # ── Structured training log (JSONL) ──
    metadata = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "model_version": version,
        "schema_version": MODEL_SCHEMA_VERSION,
        "dataset_size": len(frame),
        "train_size": len(X_train_clean),
        "test_size": len(X_test_clean),
        "class_distribution": {
            str(k): int(v) for k, v in labels.value_counts().to_dict().items()
        },
        "training_duration_seconds": round(duration, 6),
        "feature_columns": FEATURE_COLUMNS,
        "invalid_feature_cells_seen": cleaner.invalid_cells_seen_,
        "fallback_zero_features": cleaner.fallback_zero_features_,
        "metrics": report,
        "artifact": str(artifact_file),
    }

    log_file = logs_path / "training_runs.jsonl"
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(metadata, sort_keys=True) + "\n")

    LOGGER.info(
        "artifact_persisted path=%s version=%s",
        artifact_file,
        version,
    )

    return artifact_file, metadata


# ─── Loading ────────────────────────────────────────────

def load_detector(path: str | Path) -> DetectorArtifact:
    """
    Load and validate a persisted detector artifact.

    Raises ModelArtifactError if the file is missing, corrupt, or
    schema-incompatible.
    """
    try:
        artifact = joblib.load(path)
    except Exception as exc:
        raise ModelArtifactError(
            "Unable to load detector artifact."
        ) from exc

    if not isinstance(artifact, DetectorArtifact):
        raise ModelArtifactError(
            "Detector artifact is not a DetectorArtifact instance."
        )

    if artifact.schema_version != MODEL_SCHEMA_VERSION:
        raise ModelArtifactError(
            f"Schema version mismatch: expected {MODEL_SCHEMA_VERSION}, "
            f"got {artifact.schema_version}."
        )

    if tuple(artifact.feature_columns) != tuple(FEATURE_COLUMNS):
        raise ModelArtifactError(
            "Detector artifact has an incompatible feature contract."
        )

    return artifact


# ─── Inference ──────────────────────────────────────────

def predict(
    artifact: DetectorArtifact,
    features: pd.DataFrame,
) -> list[Prediction]:
    """
    Run inference on one or more feature rows.

    Validates input against the strict feature contract BEFORE passing
    to sklearn, so callers get clear typed exceptions rather than
    cryptic internal errors.

    Raises InferenceInputError on any contract violation.
    """
    if not isinstance(features, pd.DataFrame):
        raise InferenceInputError(
            "Inference input must be a pandas DataFrame."
        )

    if list(features.columns) != FEATURE_COLUMNS:
        raise InferenceInputError(
            f"Inference requires exactly {len(FEATURE_COLUMNS)} columns "
            f"in the documented order."
        )

    # Clean through the same cleaner used at training time.
    try:
        clean = artifact.cleaner.transform(features)
    except Exception as exc:
        raise InferenceInputError(
            f"Inference feature validation failed: {exc}"
        ) from exc

    # Run the model.
    try:
        labels = artifact.model.predict(clean)
        probabilities = artifact.model.predict_proba(clean)
        classes = [str(c) for c in artifact.model.classes_]
    except Exception as exc:
        raise InferenceInputError(
            "Inference failed after contract validation."
        ) from exc

    return [
        Prediction(
            label=str(label),
            probabilities={
                cls: float(prob)
                for cls, prob in zip(classes, row)
            },
        )
        for label, row in zip(labels, probabilities)
    ]
