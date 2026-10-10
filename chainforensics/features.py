from __future__ import annotations

import numpy as np
import pandas as pd

from .exceptions import SchemaValidationError


# =========================================================
# Sprint 1 Feature Contract
# =========================================================

FEATURE_COLUMNS = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]


# =========================================================
# Feature Cleaner
# =========================================================

class FeatureCleaner:
    """
    Cleans CICIDS2017 network-flow features.

    - NaN values are repaired using training-set medians.
    - Infinite values are converted to NaN.
    - Flow Duration values below zero are treated as invalid.
    - Rows are never silently deleted.
    """

    def __init__(self):
        self.medians: pd.Series | None = None

        # Metadata expected by model.py
        self.invalid_cells_seen_ = 0
        self.fallback_zero_features_ = []

    def _prepare(self, frame: pd.DataFrame) -> pd.DataFrame:

        missing = [
            column
            for column in FEATURE_COLUMNS
            if column not in frame.columns
        ]

        if missing:
            raise SchemaValidationError(
                f"Required feature columns are missing: {missing}"
            )

        # Select approved features only.
        x = frame[FEATURE_COLUMNS].copy()

        # Convert all features to numeric.
        for column in FEATURE_COLUMNS:
            x[column] = pd.to_numeric(
                x[column],
                errors="coerce"
            )

        # Replace infinite values with NaN.
        x = x.replace(
            [np.inf, -np.inf],
            np.nan
        )

        # CICIDS2017 contains Flow Duration = -1.
        # Treat negative duration as an invalid measurement.
        if "Flow Duration" in x.columns:

            invalid_duration = x["Flow Duration"] < 0

            x.loc[
                invalid_duration,
                "Flow Duration"
            ] = np.nan

        return x

    def fit(self, frame: pd.DataFrame):

        x = self._prepare(frame)

        # Count invalid cells before repairing them.
        self.invalid_cells_seen_ = int(
            x.isna().sum().sum()
        )

        # Calculate medians ONLY from training data.
        self.medians = x.median(
            numeric_only=True
        )

        # Find features that contain no usable values.
        unusable = self.medians[
            self.medians.isna()
        ].index.tolist()

        self.fallback_zero_features_ = unusable.copy()

        if unusable:
            raise SchemaValidationError(
                f"Features contain no usable training values: {unusable}"
            )

        return self

    def transform(
        self,
        frame: pd.DataFrame
    ) -> pd.DataFrame:

        if self.medians is None:
            raise SchemaValidationError(
                "FeatureCleaner must be fitted before transform()."
            )

        x = self._prepare(frame)

        # Replace invalid values with training medians.
        x = x.fillna(self.medians)

        # Final safety check.
        if not np.isfinite(
            x.to_numpy()
        ).all():

            raise SchemaValidationError(
                "Feature cleaning failed: "
                "NaN or infinite values remain."
            )

        return x

    def fit_transform(
        self,
        frame: pd.DataFrame
    ) -> pd.DataFrame:

        self.fit(frame)

        return self.transform(frame)


# =========================================================
# Feature Validation
# =========================================================

def validate_ranges(
    frame: pd.DataFrame
) -> None:

    if not isinstance(
        frame,
        pd.DataFrame
    ):
        raise SchemaValidationError(
            "Features must be a pandas DataFrame."
        )

    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in frame.columns
    ]

    if missing:
        raise SchemaValidationError(
            "Feature contract violation. "
            f"Missing columns: {missing}"
        )

    values = frame[
        FEATURE_COLUMNS
    ].to_numpy()

    if not np.isfinite(
        values
    ).all():

        raise SchemaValidationError(
            "Feature contract violation: "
            "NaN or infinite values remain."
        )


# =========================================================
# Feature / Label Split
# =========================================================

def split_features_and_labels(
    frame: pd.DataFrame
):

    """
    Split the dataframe into:

        X = network-flow features
        y = normalized attack labels

    Label is NEVER used as a model feature.
    """

    if "Label" not in frame.columns:
        raise SchemaValidationError(
            "Required label column 'Label' is missing."
        )

    missing = [
        column
        for column in FEATURE_COLUMNS
        if column not in frame.columns
    ]

    if missing:
        raise SchemaValidationError(
            "Required feature columns are missing: "
            f"{missing}"
        )

    X = frame[
        FEATURE_COLUMNS
    ].copy()

    y = frame[
        "Label"
    ].astype("string").copy()

    return X, y