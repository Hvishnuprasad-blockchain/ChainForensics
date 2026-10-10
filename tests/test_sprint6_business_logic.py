import json

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
    DetectorArtifact,
    load_detector,
    predict,
    train_and_persist,
)
from chainforensics.recovery.simulator import simulate_recovery


def make_feature_frame(rows=8):
    data = {
        column: np.full(rows, float(index + 1))
        for index, column in enumerate(FEATURE_COLUMNS)
    }

    # Make Flow Duration realistic.
    data["Flow Duration"] = np.full(rows, 1000.0)

    return pd.DataFrame(data)


def make_training_frame():
    frame = make_feature_frame(12)

    labels = (
        ["BENIGN", "DoS", "PortScan", "BruteForce"]
        * 3
    )

    frame["Label"] = labels

    # Give classes distinguishable values.
    for i, label in enumerate(labels):
        frame.loc[i, "Flow Duration"] = 1000 + i * 100
        frame.loc[i, "Total Fwd Packets"] = i + 1

    return frame


# =========================================================
# FEATURE BUSINESS LOGIC
# =========================================================

def test_feature_cleaner_repairs_nan_inf_and_negative_duration():
    frame = make_feature_frame(3)

    frame.loc[0, "Flow Duration"] = -1
    frame.loc[1, "Flow Bytes/s"] = np.inf
    frame.loc[2, "Flow Packets/s"] = np.nan

    cleaner = FeatureCleaner()
    cleaned = cleaner.fit_transform(frame)

    assert cleaned.shape == (3, len(FEATURE_COLUMNS))
    assert np.isfinite(cleaned.to_numpy()).all()
    assert cleaner.invalid_cells_seen_ >= 3


def test_feature_cleaner_requires_fit_before_transform():
    cleaner = FeatureCleaner()

    with pytest.raises(SchemaValidationError, match="fitted"):
        cleaner.transform(make_feature_frame(1))


def test_feature_cleaner_rejects_missing_feature_column():
    frame = make_feature_frame(2)
    frame = frame.drop(columns=["Flow Duration"])

    with pytest.raises(
        SchemaValidationError,
        match="Required feature columns are missing",
    ):
        FeatureCleaner().fit(frame)


def test_feature_cleaner_rejects_feature_with_no_usable_training_values():
    frame = make_feature_frame(3)
    frame["Flow Duration"] = np.nan

    with pytest.raises(
        SchemaValidationError,
        match="no usable training values",
    ):
        FeatureCleaner().fit(frame)


def test_validate_ranges_accepts_clean_features():
    frame = make_feature_frame(2)

    validate_ranges(frame)


def test_validate_ranges_rejects_non_dataframe():
    with pytest.raises(
        SchemaValidationError,
        match="pandas DataFrame",
    ):
        validate_ranges([])


def test_validate_ranges_rejects_missing_column():
    frame = make_feature_frame(2)
    frame = frame.drop(columns=["Flow Duration"])

    with pytest.raises(
        SchemaValidationError,
        match="Missing columns",
    ):
        validate_ranges(frame)


def test_validate_ranges_rejects_nan_and_infinity():
    frame = make_feature_frame(2)
    frame.loc[0, "Flow Bytes/s"] = np.nan

    with pytest.raises(
        SchemaValidationError,
        match="NaN or infinite",
    ):
        validate_ranges(frame)


def test_split_features_and_labels_returns_features_without_label():
    frame = make_training_frame()

    X, y = split_features_and_labels(frame)

    assert list(X.columns) == FEATURE_COLUMNS
    assert "Label" not in X.columns
    assert len(X) == len(y)
    assert set(y.tolist()) == {
        "BENIGN",
        "DoS",
        "PortScan",
        "BruteForce",
    }


def test_split_features_and_labels_rejects_missing_label():
    frame = make_feature_frame(2)

    with pytest.raises(
        SchemaValidationError,
        match="Label",
    ):
        split_features_and_labels(frame)


# =========================================================
# INGESTION BUSINESS LOGIC
# =========================================================

def test_load_csv_normalizes_columns_labels_and_rejects_unknown(tmp_path):
    frame = make_training_frame()

    frame = frame.rename(
        columns={
            "Flow Duration": " Flow Duration ",
            "Label": " Label ",
        }
    )

    # Include one unsupported CICIDS-style label.
    extra = frame.iloc[[0]].copy()
    extra[" Label "] = "Heartbleed"

    frame = pd.concat([frame, extra], ignore_index=True)

    path = tmp_path / "traffic.csv"
    frame.to_csv(path, index=False)

    loaded, stats = load_csv(path)

    assert "Flow Duration" in loaded.columns
    assert " Label " not in loaded.columns
    assert "Label" in loaded.columns

    assert stats.rows_read == 13
    assert stats.rows_returned == 12
    assert stats.rows_rejected == 1
    assert stats.unknown_label_rows == 1
    assert stats.leading_space_columns_fixed == 2


def test_load_csv_maps_cicids_labels(tmp_path):
    frame = make_feature_frame(4)

    frame["Label"] = [
        "BENIGN",
        "DoS Hulk",
        "FTP-Patator",
        "SSH-Patator",
    ]

    path = tmp_path / "labels.csv"
    frame.to_csv(path, index=False)

    loaded, stats = load_csv(path)

    assert loaded["Label"].tolist() == [
        "BENIGN",
        "DoS",
        "BruteForce",
        "BruteForce",
    ]
    assert stats.unknown_label_rows == 0


def test_load_csv_rejects_missing_file(tmp_path):
    missing = tmp_path / "does_not_exist.csv"

    with pytest.raises(
        SchemaValidationError,
        match="does not exist",
    ):
        load_csv(missing)


def test_load_csv_rejects_missing_label_column(tmp_path):
    frame = make_feature_frame(2)

    path = tmp_path / "missing_label.csv"
    frame.to_csv(path, index=False)

    with pytest.raises(
        SchemaValidationError,
        match="Label",
    ):
        load_csv(path)


def test_load_csv_records_inf_and_nan_cells(tmp_path):
    frame = make_feature_frame(3)

    frame.loc[0, "Flow Bytes/s"] = np.inf
    frame.loc[1, "Flow Packets/s"] = np.nan

    frame["Label"] = [
        "BENIGN",
        "DoS",
        "PortScan",
    ]

    path = tmp_path / "invalid_values.csv"
    frame.to_csv(path, index=False)

    loaded, stats = load_csv(path)

    assert len(loaded) == 3
    assert stats.inf_cells == 1
    assert stats.nan_cells == 1


# =========================================================
# MODEL BUSINESS LOGIC
# =========================================================

def test_train_load_and_predict_real_model(tmp_path):
    frame = make_training_frame()

    models_dir = tmp_path / "models"
    logs_dir = tmp_path / "logs"

    artifact_path, metadata = train_and_persist(
        frame,
        models_dir=models_dir,
        logs_dir=logs_dir,
        test_size=0.25,
        random_state=42,
    )

    assert artifact_path.exists()
    assert metadata["dataset_size"] == len(frame)
    assert metadata["model_version"].startswith("v")
    assert metadata["schema_version"] == 1

    training_log = logs_dir / "training_runs.jsonl"
    assert training_log.exists()

    lines = training_log.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    saved_metadata = json.loads(lines[0])
    assert saved_metadata["dataset_size"] == len(frame)

    artifact = load_detector(artifact_path)

    predictions = predict(
        artifact,
        frame[FEATURE_COLUMNS].iloc[:3],
    )

    assert len(predictions) == 3

    for prediction in predictions:
        assert prediction.label in {
            "BENIGN",
            "DoS",
            "PortScan",
            "BruteForce",
        }
        assert prediction.probabilities
        assert abs(sum(prediction.probabilities.values()) - 1.0) < 1e-6


def test_predict_rejects_non_dataframe(tmp_path):
    frame = make_training_frame()

    artifact_path, _ = train_and_persist(
        frame,
        models_dir=tmp_path / "models",
        logs_dir=tmp_path / "logs",
        test_size=0.25,
        random_state=42,
    )

    artifact = load_detector(artifact_path)

    with pytest.raises(
        InferenceInputError,
        match="pandas DataFrame",
    ):
        predict(artifact, [])


def test_predict_rejects_wrong_feature_contract(tmp_path):
    frame = make_training_frame()

    artifact_path, _ = train_and_persist(
        frame,
        models_dir=tmp_path / "models",
        logs_dir=tmp_path / "logs",
        test_size=0.25,
        random_state=42,
    )

    artifact = load_detector(artifact_path)

    wrong = frame[FEATURE_COLUMNS].iloc[:1].copy()
    wrong = wrong.drop(columns=[FEATURE_COLUMNS[-1]])

    with pytest.raises(
        InferenceInputError,
        match="exactly",
    ):
        predict(artifact, wrong)


def test_load_detector_rejects_invalid_artifact(tmp_path):
    invalid_path = tmp_path / "invalid.joblib"
    invalid_path.write_bytes(b"not a valid joblib artifact")

    with pytest.raises(ModelArtifactError):
        load_detector(invalid_path)


# =========================================================
# RECOVERY BUSINESS LOGIC
# =========================================================

def test_recovery_benign_is_verified():
    result = simulate_recovery(
        {"attack_type": "BENIGN"}
    )

    assert result.status == "verified"
    assert result.action == "No remediation required"


@pytest.mark.parametrize(
    "attack_type,feature,value,expected",
    [
        ("PortScan", "packet_count", 200, "verified"),
        ("PortScan", "packet_count", 201, "escalated"),
        ("DoS", "packet_count", 500, "verified"),
        ("DoS", "packet_count", 501, "escalated"),
        ("BruteForce", "failed_attempts", 20, "verified"),
        ("BruteForce", "failed_attempts", 21, "escalated"),
        ("SQLInjection", "suspicious_queries", 10, "verified"),
        ("SQLInjection", "suspicious_queries", 11, "escalated"),
    ],
)
def test_recovery_threshold_rules(
    attack_type,
    feature,
    value,
    expected,
):
    result = simulate_recovery(
        {
            "attack_type": attack_type,
            "raw_features": {
                feature: value,
            },
        }
    )

    assert result.status == expected
    assert result.attack_type == attack_type


@pytest.mark.parametrize(
    "attack_type,feature",
    [
        ("PortScan", "packet_count"),
        ("DoS", "packet_count"),
        ("BruteForce", "failed_attempts"),
        ("SQLInjection", "suspicious_queries"),
    ],
)
def test_recovery_missing_required_feature_escalates(
    attack_type,
    feature,
):
    result = simulate_recovery(
        {
            "attack_type": attack_type,
            "raw_features": {},
        }
    )

    assert result.status == "escalated"
    assert feature in result.reason


def test_recovery_rejects_boolean_as_numeric_feature():
    result = simulate_recovery(
        {
            "attack_type": "PortScan",
            "raw_features": {
                "packet_count": True,
            },
        }
    )

    assert result.status == "escalated"


def test_unknown_attack_type_requires_manual_review():
    result = simulate_recovery(
        {
            "attack_type": "UnknownAttack",
            "raw_features": {},
        }
    )

    assert result.status == "escalated"
    assert result.attack_type == "UnknownAttack"
    assert result.action == "Manual incident investigation"
