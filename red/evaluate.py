"""Binary evaluation with threshold sweeping and MCC-based scaling.

Given decision_function values from an SVM and true labels, this module:
  1. Optionally scales raw df_values to [0, 1] using MCC-based symmetric scaling
  2. Sweeps thresholds in [0, 1] to compute P / R / F1 / MCC at each point
  3. Identifies the optimal threshold (max F1) and default threshold (0.5)

This is the core evaluation logic used in both C1/C2 misuse classification
and for calibrating the decision boundary in production.
"""

import logging
import numpy as np
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    matthews_corrcoef,
    confusion_matrix,
)
from sklearn.preprocessing import MinMaxScaler

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# MCC-based symmetric scaling
# ---------------------------------------------------------------------------

def create_mcc_scaler(df_values, labels, num_samples=50, mcc_threshold=0.1):
    """Create a symmetric MinMaxScaler calibrated using MCC on training data.

    Finds the decision-function range where MCC exceeds *mcc_threshold*,
    makes it symmetric around 0, and builds a MinMaxScaler that maps
    that range to [0, 1].

    Parameters
    ----------
    df_values : np.ndarray
        Decision function values (from estimator.decision_function).
    labels : np.ndarray
        True labels (0/1).
    num_samples : int
        Number of threshold samples for MCC calculation.
    mcc_threshold : float
        Minimum MCC to consider a valid operating range.

    Returns
    -------
    scaler : MinMaxScaler
        Configured scaler mapping [df_min, df_max] → [0, 1].
    shift : float
        Shift value to center MCC optimum at 0.
    """
    # First pass: coarse scan
    iter_values = np.linspace(df_values.min(), df_values.max(), num_samples)
    mcc = _calculate_mcc_array(df_values, labels, iter_values)

    # Find range where MCC > threshold
    target_indices = np.where(mcc > mcc_threshold)[0]
    if len(target_indices) == 0:
        logger.warning("No df range with MCC > %.2f found, using full range", mcc_threshold)
        target_df_min, target_df_max = df_values.min(), df_values.max()
    else:
        target_df_min = iter_values[target_indices].min()
        target_df_max = iter_values[target_indices].max()

    # Make symmetric around 0
    if abs(target_df_min) > target_df_max:
        target_df_max = abs(target_df_min)
    elif target_df_max > abs(target_df_min):
        target_df_min = -target_df_max

    # Second pass: refine within target range
    refined_iter = np.linspace(target_df_min, target_df_max, num_samples)
    refined_mcc = _calculate_mcc_array(df_values, labels, refined_iter)

    # Calculate shift to center MCC optimum at 0
    optimum_idx = np.argmax(refined_mcc)
    shift = refined_iter[optimum_idx]

    # Build scaler
    scaler = _build_min_max_scaler(target_df_min, target_df_max)

    logger.info(
        "MCC scaler: range=[%.4f, %.4f], shift=%.4f",
        target_df_min, target_df_max, shift,
    )
    return scaler, shift


def scale_df_values(df_values, scaler, shift=0.0):
    """Apply shift and scaling to decision function values.

    Parameters
    ----------
    df_values : np.ndarray
        Raw decision function values.
    scaler : MinMaxScaler
        Calibrated scaler.
    shift : float
        Shift to center optimum at 0.

    Returns
    -------
    np.ndarray
        Scaled values clipped to [0, 1].
    """
    shifted = df_values - shift
    scaled = scaler.transform(shifted[:, np.newaxis]).flatten()
    return np.clip(scaled, 0.0, 1.0)


# ---------------------------------------------------------------------------
# Binary evaluation with threshold sweep
# ---------------------------------------------------------------------------

class BinaryEvaluation:
    """Evaluate binary classification across a range of thresholds.

    After calling .evaluate(), results are stored in arrays indexed
    by threshold position.
    """

    def __init__(self, num_thresholds=50):
        n = num_thresholds + 1
        self.thresholds = np.linspace(0, 1, n)
        self.precision = np.zeros(n)
        self.recall = np.zeros(n)
        self.f1_scores = np.zeros(n)
        self.mccs = np.zeros(n)
        self.tp = np.zeros(n)
        self.fp = np.zeros(n)
        self.tn = np.zeros(n)
        self.fn = np.zeros(n)
        self.no_skill = 0.0

    def evaluate(self, labels, scaled_scores):
        """Sweep thresholds and compute metrics.

        Parameters
        ----------
        labels : np.ndarray
            True labels (0=benign, 1=malicious).
        scaled_scores : np.ndarray
            Scaled decision function values in [0, 1].
        """
        for i, threshold in enumerate(self.thresholds):
            pred = np.where(scaled_scores >= threshold, 1, 0)
            self.precision[i] = precision_score(labels, pred, zero_division=0)
            self.recall[i] = recall_score(labels, pred, zero_division=0)
            self.f1_scores[i] = f1_score(labels, pred, zero_division=0)
            self.mccs[i] = matthews_corrcoef(labels, pred)
            tn, fp, fn, tp = confusion_matrix(labels, pred, labels=[0, 1]).ravel()
            self.tn[i], self.fp[i], self.fn[i], self.tp[i] = tn, fp, fn, tp

        self.no_skill = labels.sum() / len(labels) if len(labels) else 0.0
        logger.info("Evaluation done: %d thresholds, no_skill=%.4f", len(self.thresholds), self.no_skill)

    def optimal_threshold_idx(self):
        """Index of threshold with maximum F1-score."""
        return int(np.argmax(self.f1_scores))

    def default_threshold_idx(self):
        """Index of threshold closest to 0.5."""
        idx = np.where(self.thresholds == 0.5)[0]
        if len(idx) > 0:
            return int(idx[0])
        return len(self.thresholds) // 2

    def summary(self):
        """Return dict with optimal and default threshold metrics."""
        opt = self.optimal_threshold_idx()
        dft = self.default_threshold_idx()
        return {
            "optimal": self._metrics_at(opt),
            "default_0.5": self._metrics_at(dft),
        }

    def _metrics_at(self, idx):
        return {
            "threshold": float(self.thresholds[idx]),
            "precision": float(self.precision[idx]),
            "recall": float(self.recall[idx]),
            "f1": float(self.f1_scores[idx]),
            "mcc": float(self.mccs[idx]),
            "tp": int(self.tp[idx]),
            "tn": int(self.tn[idx]),
            "fp": int(self.fp[idx]),
            "fn": int(self.fn[idx]),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _calculate_mcc_array(df_values, labels, iter_values):
    mcc = np.zeros(len(iter_values))
    for i, threshold in enumerate(iter_values):
        pred = np.where(df_values >= threshold, 1, 0)
        mcc[i] = matthews_corrcoef(labels, pred)
    return mcc


def _build_min_max_scaler(min_val, max_val):
    scaler = MinMaxScaler()
    scaler.data_min_ = np.array([min_val])
    scaler.data_max_ = np.array([max_val])
    data_range = max_val - min_val
    scaler.data_range_ = np.array([data_range])
    scaler.scale_ = np.array([1.0 / data_range]) if data_range != 0 else np.array([1.0])
    scaler.min_ = np.array([0.0 - min_val * scaler.scale_[0]])
    scaler.n_features_in_ = 1
    scaler.feature_range = (0, 1)
    return scaler
