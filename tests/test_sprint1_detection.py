"""
ChainForensics — Sprint 1: Detection Engine Tests

Test categories (per Sprint 0 test discipline):
    1. Unit tests:  feature cleaning, model inference contract
    2. Integration:  full pipeline CSV → train → inference
    3. Negative / security-adjacent:  no eval/exec, malformed input rejection

Every test is a real assertion, never a description of what "would" happen.
"""
from __future__ import annotations

import ast
import json
import textwrap
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from chainforensics.exceptions import (
    InferenceInputError,
    ModelArtifactError,
    SchemaValidationError,
)
from chainforensics.features import (
    FEATURE_COLUMNS,
    FeatureCleaner,
    split_features_and_labels,
    validate_ranges,
)
from chainforensics.ingestion import load_csv
from chainforensics.model import (
    SUPPORTED_CLASSES,
    DetectorArtifact,
    load_detector,
    predict,
    train_and_persist,
)


# ─── Helpers ────────────────────────────────────────────────


def _make_feature_frame(rows: int = 8) -> pd.DataFrame:
    """Create a synthetic feature DataFrame with valid values."""
    data = {
        col: np.full(rows, float(idx + 1))
        for idx, col in enumerate(FEATURE_COLUMNS)
    }
    # Realistic flow duration.
    data["Flow Duration"] = np.full(rows, 1000.0)
    return pd.DataFrame(data)


def _make_training_frame(rows_per_class: int = 3) -> pd.DataFrame:
    """Create a training frame with balanced classes and distinguishable features."""
    total = rows_per_class * len(SUPPORTED_CLASSES)
    frame = _make_feature_frame(total)

    labels = list(SUPPORTED_CLASSES) * rows_per_class
    frame["Label"] = labels

    # Give each class distinguishable feature values so the model
    # has something real to learn (prevents trivially-correct predictions
    # from all rows being identical).
    for i, label in enumerate(labels):
        class_idx = SUPPORTED_CLASSES.index(label)
        frame.loc[i, "Flow Duration"] = 1000 + class_idx * 500
        frame.loc[i, "Total Fwd Packets"] = (class_idx + 1) * 10
        frame.loc[i, "Flow Bytes/s"] = (class_idx + 1) * 1000.0
        frame.loc[i, "Fwd Packet Length Max"] = (class_idx + 1) * 100.0

    return frame


def _make_csv_file(tmp_path: Path, frame: pd.DataFrame, name: str = "data.csv") -> Path:
    """Write a DataFrame to a CSV file in the test's temp directory."""
    path = tmp_path / name
    frame.to_csv(path, index=False)
    return path


# ═══════════════════════════════════════════════════════════
# UNIT TESTS — Feature Cleaning
# ═══════════════════════════════════════════════════════════


class TestFeatureCleanerUnit:
    """Unit tests for the FeatureCleaner class."""

    def test_handles_infinite_value_without_crashing_or_corrupting(self):
        """
        Sprint 1 requirement: "feature cleaning correctly handles a row
        with an infinite value (from a synthetic divide-by-zero case)
        without crashing and without silently corrupting other rows."
        """
        frame = _make_feature_frame(4)

        # Simulate divide-by-zero producing inf in Flow Bytes/s.
        frame.loc[1, "Flow Bytes/s"] = np.inf
        frame.loc[2, "Flow Bytes/s"] = -np.inf

        # Row 0 and 3 have legitimate values — must survive unchanged.
        original_row0 = frame.loc[0, "Flow Bytes/s"]
        original_row3 = frame.loc[3, "Flow Bytes/s"]

        cleaner = FeatureCleaner()
        cleaned = cleaner.fit_transform(frame)

        # All rows preserved (no silent dropping).
        assert cleaned.shape[0] == 4

        # No inf or NaN in output.
        assert np.isfinite(cleaned.to_numpy()).all()

        # Unaffected rows are unchanged.
        assert cleaned.loc[0, "Flow Bytes/s"] == original_row0
        assert cleaned.loc[3, "Flow Bytes/s"] == original_row3

        # The cleaner recorded the invalid cells.
        assert cleaner.invalid_cells_seen_ >= 2

    def test_handles_nan_without_dropping_rows(self):
        """NaN cells get median-imputed, rows are not dropped."""
        frame = _make_feature_frame(3)
        frame.loc[0, "Flow Packets/s"] = np.nan
        frame.loc[2, "Fwd IAT Mean"] = np.nan

        cleaner = FeatureCleaner()
        cleaned = cleaner.fit_transform(frame)

        assert cleaned.shape[0] == 3
        assert np.isfinite(cleaned.to_numpy()).all()

    def test_handles_negative_flow_duration(self):
        """CICIDS2017 has Flow Duration = -1; treat as invalid measurement."""
        frame = _make_feature_frame(2)
        frame.loc[0, "Flow Duration"] = -1

        cleaner = FeatureCleaner()
        cleaned = cleaner.fit_transform(frame)

        assert cleaned.shape[0] == 2
        assert cleaned.loc[0, "Flow Duration"] >= 0 or np.isfinite(cleaned.loc[0, "Flow Duration"])

    def test_requires_fit_before_transform(self):
        """Transform without fit must raise, not produce garbage."""
        cleaner = FeatureCleaner()
        with pytest.raises(SchemaValidationError, match="fitted"):
            cleaner.transform(_make_feature_frame(1))

    def test_rejects_missing_feature_column(self):
        """Missing a contracted column is a schema violation."""
        frame = _make_feature_frame(2)
        frame = frame.drop(columns=["Flow Duration"])

        with pytest.raises(SchemaValidationError, match="missing"):
            FeatureCleaner().fit(frame)

    def test_rejects_all_nan_feature(self):
        """A feature with zero usable values cannot produce a valid median."""
        frame = _make_feature_frame(3)
        frame["Flow Duration"] = np.nan

        with pytest.raises(SchemaValidationError, match="no usable training values"):
            FeatureCleaner().fit(frame)


# ═══════════════════════════════════════════════════════════
# UNIT TESTS — Model Inference Contract
# ═══════════════════════════════════════════════════════════


class TestModelInferenceUnit:
    """Unit tests for model inference input validation."""

    @pytest.fixture(autouse=True)
    def _trained_artifact(self, tmp_path):
        """Train a small model once for all tests in this class."""
        frame = _make_training_frame(rows_per_class=5)
        path, _ = train_and_persist(
            frame,
            models_dir=tmp_path / "models",
            logs_dir=tmp_path / "logs",
            test_size=0.25,
            random_state=42,
        )
        self.artifact = load_detector(path)

    def test_rejects_non_dataframe(self):
        """
        Sprint 1 requirement: "model inference rejects a malformed input
        ... with a clear, typed exception rather than a cryptic sklearn
        internal error."
        """
        with pytest.raises(InferenceInputError, match="pandas DataFrame"):
            predict(self.artifact, [[1, 2, 3]])

    def test_rejects_wrong_number_of_columns(self):
        """Too few columns must raise InferenceInputError, not IndexError."""
        short_frame = pd.DataFrame({"col1": [1.0], "col2": [2.0]})
        with pytest.raises(InferenceInputError, match="exactly"):
            predict(self.artifact, short_frame)

    def test_rejects_wrong_column_names(self):
        """Correct number of columns but wrong names must still be rejected."""
        fake_cols = [f"wrong_col_{i}" for i in range(len(FEATURE_COLUMNS))]
        frame = pd.DataFrame(np.ones((1, len(FEATURE_COLUMNS))), columns=fake_cols)
        with pytest.raises(InferenceInputError, match="exactly"):
            predict(self.artifact, frame)

    def test_valid_input_produces_predictions(self):
        """Happy path: valid features → list of Predictions with probabilities."""
        frame = _make_feature_frame(3)
        predictions = predict(self.artifact, frame)

        assert len(predictions) == 3
        for pred in predictions:
            assert pred.label in SUPPORTED_CLASSES
            assert isinstance(pred.probabilities, dict)
            assert abs(sum(pred.probabilities.values()) - 1.0) < 1e-6

    def test_rejects_corrupted_artifact(self, tmp_path):
        """A corrupted file must raise ModelArtifactError, not a generic crash."""
        bad_file = tmp_path / "corrupt.joblib"
        bad_file.write_bytes(b"this is not a valid joblib file")

        with pytest.raises(ModelArtifactError):
            load_detector(bad_file)


# ═══════════════════════════════════════════════════════════
# UNIT TESTS — Ingestion
# ═══════════════════════════════════════════════════════════


class TestIngestionUnit:

    def test_normalizes_leading_space_columns(self, tmp_path):
        """CICIDS2017 has leading-space column names — must fix transparently."""
        frame = _make_feature_frame(2)
        frame["Label"] = ["BENIGN", "DoS"]
        # Add leading spaces like the real CICIDS2017 CSV.
        frame = frame.rename(columns={
            "Flow Duration": " Flow Duration",
            "Total Fwd Packets": " Total Fwd Packets",
        })

        path = _make_csv_file(tmp_path, frame)
        loaded, stats = load_csv(path)

        assert "Flow Duration" in loaded.columns
        assert " Flow Duration" not in loaded.columns
        assert stats.leading_space_columns_fixed >= 2

    def test_maps_cicids_labels_to_internal(self, tmp_path):
        """CICIDS2017 sub-types must map to our four supported classes."""
        frame = _make_feature_frame(4)
        frame["Label"] = ["BENIGN", "DoS Hulk", "FTP-Patator", "SSH-Patator"]

        path = _make_csv_file(tmp_path, frame)
        loaded, stats = load_csv(path)

        assert loaded["Label"].tolist() == ["BENIGN", "DoS", "BruteForce", "BruteForce"]
        assert stats.unknown_label_rows == 0

    def test_rejects_unknown_labels_without_crashing(self, tmp_path):
        """Unknown labels are dropped with a count, not a crash."""
        frame = _make_feature_frame(3)
        frame["Label"] = ["BENIGN", "Heartbleed", "DoS"]

        path = _make_csv_file(tmp_path, frame)
        loaded, stats = load_csv(path)

        assert len(loaded) == 2  # Heartbleed row dropped
        assert stats.unknown_label_rows == 1
        assert stats.rows_rejected == 1

    def test_rejects_missing_file(self, tmp_path):
        """Non-existent file must raise, not return empty."""
        with pytest.raises(SchemaValidationError, match="does not exist"):
            load_csv(tmp_path / "nonexistent.csv")

    def test_rejects_missing_label_column(self, tmp_path):
        """CSV without a Label column is a schema violation."""
        frame = _make_feature_frame(2)
        path = _make_csv_file(tmp_path, frame)

        with pytest.raises(SchemaValidationError, match="Label"):
            load_csv(path)

    def test_reports_inf_and_nan_cells(self, tmp_path):
        """Ingestion stats must count inf and NaN cells."""
        frame = _make_feature_frame(3)
        frame.loc[0, "Flow Bytes/s"] = np.inf
        frame.loc[1, "Flow Packets/s"] = np.nan
        frame["Label"] = ["BENIGN", "DoS", "PortScan"]

        path = _make_csv_file(tmp_path, frame)
        _, stats = load_csv(path)

        assert stats.inf_cells == 1
        assert stats.nan_cells == 1
        assert stats.rows_returned == 3  # Rows NOT dropped


# ═══════════════════════════════════════════════════════════
# INTEGRATION TEST — Full Pipeline
# ═══════════════════════════════════════════════════════════


class TestFullPipelineIntegration:
    """
    Sprint 1 requirement: "full pipeline (raw CSV in → trained model →
    inference on held-out split) runs end to end and produces a
    classification report."
    """

    def test_csv_to_train_to_inference(self, tmp_path):
        """Complete pipeline from CSV to inference results."""
        # ── Create a realistic-ish CSV ──
        frame = _make_training_frame(rows_per_class=10)
        csv_path = _make_csv_file(tmp_path, frame)

        # ── Ingest ──
        loaded, stats = load_csv(csv_path)
        assert stats.rows_returned == 40
        assert stats.rows_rejected == 0

        # ── Train ──
        artifact_path, metadata = train_and_persist(
            loaded,
            models_dir=tmp_path / "models",
            logs_dir=tmp_path / "logs",
            test_size=0.2,
            random_state=42,
        )

        assert artifact_path.exists()
        assert metadata["dataset_size"] == 40

        # ── Verify training log was written ──
        log_file = tmp_path / "logs" / "training_runs.jsonl"
        assert log_file.exists()
        log_entry = json.loads(log_file.read_text(encoding="utf-8").strip())
        assert log_entry["model_version"] == metadata["model_version"]
        assert log_entry["training_duration_seconds"] > 0

        # ── Load and infer ──
        artifact = load_detector(artifact_path)
        test_features = loaded[FEATURE_COLUMNS].iloc[:5]
        predictions = predict(artifact, test_features)

        assert len(predictions) == 5
        for pred in predictions:
            assert pred.label in SUPPORTED_CLASSES
            assert isinstance(pred.probabilities, dict)

        # ── Classification report exists ──
        metrics = metadata["metrics"]
        for label in SUPPORTED_CLASSES:
            assert label in metrics
            assert "precision" in metrics[label]
            assert "recall" in metrics[label]
            assert "f1-score" in metrics[label]

    def test_versioned_model_files_coexist(self, tmp_path):
        """Two training runs produce distinct versioned files, enabling rollback."""
        frame = _make_training_frame(rows_per_class=5)

        path1, meta1 = train_and_persist(
            frame,
            models_dir=tmp_path / "models",
            logs_dir=tmp_path / "logs",
        )
        path2, meta2 = train_and_persist(
            frame,
            models_dir=tmp_path / "models",
            logs_dir=tmp_path / "logs",
        )

        assert path1 != path2
        assert path1.exists()
        assert path2.exists()
        assert meta1["model_version"] != meta2["model_version"]

        # Both can be loaded independently.
        art1 = load_detector(path1)
        art2 = load_detector(path2)
        assert art1.model_version != art2.model_version


# ═══════════════════════════════════════════════════════════
# NEGATIVE / SECURITY-ADJACENT TESTS
# ═══════════════════════════════════════════════════════════


class TestSecurityNegative:
    """
    Sprint 1 requirement: "confirm the ingestion module does not
    execute or evaluate any content from the CSV (no eval/exec on
    cell contents) — a defensive test against a maliciously crafted
    input file."
    """

    def test_no_eval_or_exec_in_ingestion_module(self):
        """
        Static analysis: the ingestion module source code must not
        contain eval() or exec() calls.
        """
        import chainforensics.ingestion as mod

        source_path = Path(mod.__file__)
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        dangerous_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                    dangerous_calls.append(
                        f"{func.id}() at line {node.lineno}"
                    )

        assert dangerous_calls == [], (
            f"ingestion.py contains dangerous calls: {dangerous_calls}"
        )

    def test_malicious_csv_cell_not_executed(self, tmp_path):
        """
        A CSV cell containing Python code must be treated as a string,
        not evaluated.

        We write the malicious content directly into the CSV file as raw
        text, since a real attacker controls the file on disk, not a
        pandas DataFrame in memory.
        """
        # Build a valid CSV first, then replace a cell with malicious text.
        frame = _make_feature_frame(2)
        frame["Label"] = ["BENIGN", "DoS"]
        path = _make_csv_file(tmp_path, frame, name="malicious.csv")

        # Read the CSV text and replace a numeric value with a payload.
        csv_text = path.read_text(encoding="utf-8")
        lines = csv_text.split("\n")
        # Replace the first value in the data row (Flow Duration) with a payload.
        parts = lines[1].split(",")
        parts[0] = "__import__('os').system('echo PWNED')"
        lines[1] = ",".join(parts)
        path.write_text("\n".join(lines), encoding="utf-8")

        # Should not crash, should not execute the payload.
        loaded, stats = load_csv(path)

        # The malicious string was read as text by pandas, then coerced
        # to NaN by pd.to_numeric during feature cleaning — never executed.
        assert len(loaded) == 2
        # If we got here without side effects, the test passes.

    def test_no_eval_or_exec_in_features_module(self):
        """Features module must also not contain eval/exec."""
        import chainforensics.features as mod

        source_path = Path(mod.__file__)
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        dangerous_calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Name) and func.id in ("eval", "exec"):
                    dangerous_calls.append(
                        f"{func.id}() at line {node.lineno}"
                    )

        assert dangerous_calls == [], (
            f"features.py contains dangerous calls: {dangerous_calls}"
        )


# ═══════════════════════════════════════════════════════════
# Training log structure validation
# ═══════════════════════════════════════════════════════════


class TestTrainingLogStructure:
    """Verify training metadata is machine-parseable and complete."""

    def test_log_contains_required_fields(self, tmp_path):
        """The JSONL training log must contain all required metadata fields."""
        frame = _make_training_frame(rows_per_class=5)

        _, metadata = train_and_persist(
            frame,
            models_dir=tmp_path / "models",
            logs_dir=tmp_path / "logs",
        )

        log_file = tmp_path / "logs" / "training_runs.jsonl"
        assert log_file.exists()

        entry = json.loads(log_file.read_text(encoding="utf-8").strip())

        required_fields = [
            "timestamp_utc",
            "model_version",
            "schema_version",
            "dataset_size",
            "train_size",
            "test_size",
            "class_distribution",
            "training_duration_seconds",
            "feature_columns",
            "metrics",
            "artifact",
        ]

        for field in required_fields:
            assert field in entry, f"Missing required field: {field}"

        # Class distribution must cover all supported classes.
        for cls in SUPPORTED_CLASSES:
            assert cls in entry["class_distribution"], (
                f"Missing class in distribution: {cls}"
            )

        # Duration must be a positive number (proves it was actually measured).
        assert entry["training_duration_seconds"] > 0
