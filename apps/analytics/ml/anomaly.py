"""
Anomaly detection using Isolation Forest.

Uses scikit-learn's IsolationForest algorithm to identify log entries that
deviate significantly from normal patterns. Falls back to z-score-based
detection when there are not enough samples for model training.
"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import pandas as pd
import logging

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect anomalous log entries using Isolation Forest.

    The detector first attempts to train an Isolation Forest model on the
    provided feature data. If there are fewer than ``min_samples`` entries,
    it falls back to a simple z-score-based approach.

    Attributes:
        contamination: Expected proportion of anomalies in the data (0-0.5).
        model: Trained IsolationForest instance or ``None``.
        scaler: StandardScaler used to normalise features before training.
        is_trained: Whether the model has been successfully trained.
        min_samples: Minimum number of entries required for training.
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.min_samples = 10

    def train(self, features_df: pd.DataFrame) -> bool:
        """Train the Isolation Forest model on feature data.

        Args:
            features_df: DataFrame of numerical features (one row per entry).

        Returns:
            True if training succeeded, False otherwise.
        """
        if len(features_df) < self.min_samples:
            logger.warning(
                f"Not enough samples ({len(features_df)}) for anomaly detection. "
                f"Need {self.min_samples}."
            )
            return False

        try:
            # Keep only numeric columns and sanitise
            features_clean = features_df.select_dtypes(include=[np.number]).fillna(0)
            features_clean = features_clean.replace([np.inf, -np.inf], 0)

            if features_clean.empty or features_clean.shape[1] == 0:
                logger.warning("No numeric features available for anomaly detection.")
                return False

            self.scaler.fit(features_clean)
            scaled = self.scaler.transform(features_clean)

            self.model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
            )
            self.model.fit(scaled)
            self.is_trained = True
            logger.info(
                f"Anomaly detector trained on {len(features_df)} samples "
                f"with {features_clean.shape[1]} features."
            )
            return True
        except Exception as exc:
            logger.error(f"Failed to train anomaly detector: {exc}")
            self.is_trained = False
            return False

    def predict(self, features_df: pd.DataFrame) -> np.ndarray:
        """Return anomaly scores for each entry.

        Scores are normalised to the 0-1 range where **1 = most anomalous**.

        If the model has not been trained, the method falls back to z-score
        based detection.

        Args:
            features_df: DataFrame with the same feature columns used during
                training.

        Returns:
            1-D numpy array of anomaly scores in [0, 1].
        """
        if not self.is_trained:
            return self._zscore_fallback(features_df)

        try:
            features_clean = features_df.select_dtypes(include=[np.number]).fillna(0)
            features_clean = features_clean.replace([np.inf, -np.inf], 0)

            if features_clean.empty or features_clean.shape[1] == 0:
                return np.zeros(len(features_df))

            scaled = self.scaler.transform(features_clean)

            # decision_function: negative values indicate anomalies
            raw_scores = self.model.decision_function(scaled)

            # Normalise to 0-1 where 1 = most anomalous
            min_score = raw_scores.min()
            max_score = raw_scores.max()
            if max_score == min_score:
                return np.zeros(len(raw_scores))
            normalized = 1 - (raw_scores - min_score) / (max_score - min_score)
            return normalized
        except Exception as exc:
            logger.error(f"Anomaly prediction failed, using z-score fallback: {exc}")
            return self._zscore_fallback(features_df)

    def _zscore_fallback(self, features_df: pd.DataFrame) -> np.ndarray:
        """Simple z-score based anomaly detection as fallback.

        Computes the maximum absolute z-score across all numeric features for
        each row, then normalises the result to [0, 1].

        Args:
            features_df: DataFrame of features.

        Returns:
            1-D numpy array of anomaly scores in [0, 1].
        """
        try:
            features_clean = features_df.select_dtypes(include=[np.number]).fillna(0)
            if features_clean.empty or features_clean.shape[1] == 0:
                return np.zeros(len(features_df))

            means = features_clean.mean()
            stds = features_clean.std().replace(0, 1)
            z_scores = ((features_clean - means) / stds).abs()
            max_z = z_scores.max(axis=1)

            max_val = max_z.max()
            if max_val == 0:
                return np.zeros(len(features_df))
            return (max_z / max_val).values
        except Exception as exc:
            logger.error(f"Z-score fallback failed: {exc}")
            return np.zeros(len(features_df))
