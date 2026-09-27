"""SVM / LR / CNB model training with hyperparameter optimization.

Supports GPU acceleration via RAPIDS cuML if available,
falls back to sklearn CPU automatically.

Also provides an EnsembleClassifier that combines decision-function
scores from heterogeneous base classifiers into a single calibrated
score, compatible with the rest of the pipeline (validate / evaluate).

GPU mode (RAPIDS cuML):
    pip install cuml-cu12  # or matching CUDA version

CPU mode (sklearn):
    pip install scikit-learn
"""

import logging
import os
import numpy as np
from sklearn.model_selection import GridSearchCV, StratifiedKFold
from sklearn.metrics import f1_score, matthews_corrcoef, make_scorer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import ComplementNB
from tqdm import tqdm

logger = logging.getLogger(__name__)

# Auto-detect acceleration backend (priority: NVIDIA GPU > Intel CPU > plain CPU)
GPU_AVAILABLE = False
INTEL_AVAILABLE = False

# RED_DISABLE_INTELEX=1 → bỏ qua Intel oneDAL, dùng pure sklearn. Cần khi model phải chạy
# portable trên CPU khác: oneDAL fit drop cột zero-coef (coef_ < n_features_in_) → model
# lệch dim, inference oneDAL ném std::bad_alloc trên CPU khác. Xem red_linux/CLAUDE.md.
_DISABLE_INTELEX = os.environ.get("RED_DISABLE_INTELEX", "1") == "1"

try:
    from cuml.svm import SVC as cuSVC
    GPU_AVAILABLE = True
    logger.info("RAPIDS cuML detected — using NVIDIA GPU-accelerated SVM")
except ImportError:
    if _DISABLE_INTELEX:
        logger.info("RED_DISABLE_INTELEX=1 — skipping Intel oneDAL, using plain sklearn CPU SVM")
    else:
        try:
            from sklearnex import patch_sklearn
            patch_sklearn()  # patches sklearn.svm.SVC in-place with Intel oneDAL
            INTEL_AVAILABLE = True
            logger.info("Intel Extension for scikit-learn detected — using Intel CPU acceleration")
        except ImportError:
            logger.info("No acceleration found — using plain sklearn CPU SVM")

from sklearn.svm import SVC, LinearSVC

DEFAULT_PARAM_GRID = {
    "C": np.logspace(-2, 1, num=20),
    "kernel": ["linear"],
    "class_weight": ["balanced"],
}

# Seed for all CV splits / SVC / LR. Default 42 (reproducible, Windows pipeline
# unchanged). Override via env RED_SEED to run multi-seed ablation (RED-Linux V3 fix).
RANDOM_STATE = int(os.environ.get("RED_SEED", "42"))

SCORERS = {
    "f1": f1_score,
    "mcc": matthews_corrcoef,
}


def train_svc_gridsearch(X, y, param_grid=None, scoring="f1", cv=5, n_jobs=-1):
    """Train SVC using GridSearchCV for hyperparameter optimization.

    Uses GPU (cuML) if available, otherwise falls back to sklearn CPU.
    For GPU mode, GridSearchCV still runs on CPU but individual SVC fits use GPU.

    Parameters
    ----------
    X : array-like
    y : array-like
    param_grid : dict, optional
    scoring : str — "f1" or "mcc"
    cv : int — cross-validation folds
    n_jobs : int — parallel jobs (-1 = all cores)
    """
    if param_grid is None:
        param_grid = DEFAULT_PARAM_GRID

    scorer_fn = SCORERS.get(scoring, f1_score)
    scorer = make_scorer(scorer_fn)

    n_combinations = _count_combinations(param_grid)
    total_fits = n_combinations * cv
    logger.info("GridSearchCV: %d combinations × %d folds = %d fits", n_combinations, cv, total_fits)

    if GPU_AVAILABLE:
        logger.info("GPU mode: grid search on CPU → final fit on GPU")
        best_params, best_score = _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs)
        estimator = _fit_gpu_svc(X, y, best_params)
        return estimator, best_params, best_score

    # CPU mode using sklearn GridSearchCV — parallel via n_jobs (huge speedup vs manual loop)
    cv_splitter = StratifiedKFold(n_splits=cv, shuffle=True, random_state=RANDOM_STATE)
    gs = GridSearchCV(
        SVC(cache_size=2000, random_state=RANDOM_STATE),
        param_grid=param_grid,
        scoring=scorer,
        cv=cv_splitter,
        n_jobs=n_jobs,
        verbose=1,
        refit=True,
    )
    gs.fit(X, y)
    logger.info("Best params: %s  Best score: %.4f", gs.best_params_, gs.best_score_)
    return gs.best_estimator_, gs.best_params_, gs.best_score_


def _cpu_grid_search(X, y, param_grid, scorer, cv, n_jobs):
    """Run GridSearchCV on CPU to find best params (used in GPU mode)."""
    from sklearn.svm import SVC as skSVC
    from sklearn.metrics import f1_score
    scorer_fn = SCORERS.get("f1", f1_score)
    param_list = list(_iter_param_grid(param_grid))
    best_score = -np.inf
    best_params = None

    with tqdm(total=len(param_list), desc="GridSearch (CPU→GPU)", unit="param", ncols=80) as pbar:
        for params in param_list:
            kf = StratifiedKFold(n_splits=cv)
            scores = []
            for train_idx, val_idx in kf.split(X, y):
                svc = skSVC(cache_size=2000, **params)
                svc.fit(X[train_idx], y[train_idx])
                pred = svc.predict(X[val_idx])
                scores.append(scorer_fn(y[val_idx], pred))
            mean_score = np.mean(scores)
            if mean_score > best_score:
                best_score = mean_score
                best_params = params
            pbar.set_postfix({"best": f"{best_score:.4f}"})
            pbar.update(1)

    logger.info("Best params: %s  Best score: %.4f", best_params, best_score)
    return best_params, best_score


def _fit_gpu_svc(X, y, params):
    """Fit final SVC on GPU using cuML."""
    import cupy as cp
    X_gpu = cp.array(X.toarray() if hasattr(X, 'toarray') else X)
    y_gpu = cp.array(y)
    svc = cuSVC(
        C=params.get("C", 1.0),
        kernel=params.get("kernel", "linear"),
        class_weight=params.get("class_weight", "balanced"),
    )
    logger.info("Fitting final SVC on GPU...")
    svc.fit(X_gpu, y_gpu)
    return svc


def train_svc_fixed(X, y, C=1.0, kernel="linear", class_weight="balanced"):
    """Train SVC with fixed parameters. Uses GPU if available."""
    if GPU_AVAILABLE:
        return _fit_gpu_svc(X, y, {"C": C, "kernel": kernel, "class_weight": class_weight})

    svc = SVC(C=C, kernel=kernel, class_weight=class_weight,
              cache_size=2000, random_state=RANDOM_STATE)
    svc.fit(X, y)
    logger.info("Trained SVC with C=%.4f, kernel=%s, class_weight=%s", C, kernel, class_weight)
    return svc


def _count_combinations(param_grid):
    count = 1
    for values in param_grid.values():
        count *= len(values)
    return count


def _iter_param_grid(param_grid):
    """Yield all parameter combinations from a param grid dict."""
    from itertools import product
    keys = list(param_grid.keys())
    for values in product(*param_grid.values()):
        yield dict(zip(keys, values))


# ---------------------------------------------------------------------------
# Logistic Regression — probabilistic linear classifier
# ---------------------------------------------------------------------------

LR_PARAM_GRID = {
    "C": np.logspace(-2, 1, num=10),
    "class_weight": ["balanced"],
}


def train_lr_gridsearch(X, y, param_grid=None, scoring="f1", cv=5, n_jobs=-1):
    """Train LogisticRegression using sklearn GridSearchCV (parallel via n_jobs)."""
    if param_grid is None:
        param_grid = LR_PARAM_GRID

    scorer_fn = SCORERS.get(scoring, f1_score)
    scorer = make_scorer(scorer_fn)

    n_combinations = _count_combinations(param_grid)
    logger.info(
        "LR GridSearchCV: %d combinations × %d folds = %d fits (n_jobs=%d)",
        n_combinations, cv, n_combinations * cv, n_jobs,
    )

    cv_splitter = StratifiedKFold(n_splits=cv, shuffle=True, random_state=RANDOM_STATE)
    gs = GridSearchCV(
        LogisticRegression(solver="liblinear", max_iter=1000, random_state=RANDOM_STATE),
        param_grid=param_grid,
        scoring=scorer,
        cv=cv_splitter,
        n_jobs=n_jobs,
        verbose=1,
        refit=True,
    )
    gs.fit(X, y)
    logger.info("LR best params: %s  best score: %.4f", gs.best_params_, gs.best_score_)
    return gs.best_estimator_, gs.best_params_, gs.best_score_


# ---------------------------------------------------------------------------
# Complement Naive Bayes — text-friendly, fast, handles imbalance
# ---------------------------------------------------------------------------

def train_cnb(X, y, alpha=1.0):
    """Train ComplementNB. Requires non-negative features (TF-IDF/Count are OK)."""
    cnb = ComplementNB(alpha=alpha)
    cnb.fit(X, y)
    logger.info("Trained ComplementNB with alpha=%.4f", alpha)
    return cnb


# ---------------------------------------------------------------------------
# Ensemble — soft-voting over heterogeneous classifiers
# ---------------------------------------------------------------------------

class EnsembleClassifier:
    """Weighted soft-voting ensemble exposing decision_function().

    Each base classifier produces a raw score:
      - if it has decision_function(): use that directly
      - else: derive log-odds from predict_proba (log(p1 / p0))

    Raw scores are z-score normalised on training data so that classifiers
    with different output scales contribute comparably. The final
    decision_function is the weighted average of normalised scores.

    The class is intentionally compatible with the existing pipeline:
    validate.py only requires .decision_function(X), and create_mcc_scaler
    re-maps the output to [0, 1] downstream.
    """

    def __init__(self, classifiers, weights=None):
        self.classifiers = dict(classifiers)
        self.weights = dict(weights) if weights else {n: 1.0 for n in self.classifiers}
        self.score_means: dict = {}
        self.score_stds: dict = {}

    def _raw_scores(self, name, X):
        clf = self.classifiers[name]
        if hasattr(X, "toarray") and hasattr(clf, "support_vectors_"):
            X = X.toarray()
        if hasattr(clf, "decision_function"):
            return np.asarray(clf.decision_function(X)).ravel()
        proba = clf.predict_proba(X)
        eps = 1e-9
        return np.log((proba[:, 1] + eps) / (proba[:, 0] + eps))

    def calibrate(self, X):
        """Compute per-classifier mean/std of raw scores on training data."""
        for name in self.classifiers:
            scores = self._raw_scores(name, X)
            self.score_means[name] = float(scores.mean())
            std = float(scores.std())
            self.score_stds[name] = std if std > 1e-12 else 1.0
            logger.info(
                "Ensemble calibration [%s]: mean=%.4f std=%.4f",
                name, self.score_means[name], self.score_stds[name],
            )

    def decision_function(self, X):
        total = np.zeros(X.shape[0], dtype=np.float64)
        total_weight = 0.0
        for name in self.classifiers:
            scores = self._raw_scores(name, X)
            mean = self.score_means.get(name, 0.0)
            std = self.score_stds.get(name, 1.0)
            normalized = (scores - mean) / std
            w = float(self.weights.get(name, 1.0))
            total += w * normalized
            total_weight += w
        return total / total_weight if total_weight > 0 else total

    def predict(self, X):
        return (self.decision_function(X) >= 0).astype(int)

    def get_params(self, deep=True):
        return {
            "members": list(self.classifiers.keys()),
            "weights": self.weights,
            "score_means": self.score_means,
            "score_stds": self.score_stds,
        }


def train_ensemble(X, y, scoring="f1", cv=5, n_jobs=-1, members=("svm", "lr", "cnb")):
    """Train the requested base classifiers and wrap them in an EnsembleClassifier.

    Returns
    -------
    ensemble : EnsembleClassifier
    member_params : dict
        Best hyperparameters per member (for logging / persistence).
    member_scores : dict
        Cross-validated best score per member.
    """
    classifiers = {}
    member_params = {}
    member_scores = {}

    if "svm" in members:
        logger.info("Training SVM member...")
        svc, svc_params, svc_score = train_svc_gridsearch(
            X, y, scoring=scoring, cv=cv, n_jobs=n_jobs,
        )
        classifiers["svm"] = svc
        member_params["svm"] = svc_params
        member_scores["svm"] = svc_score

    if "lr" in members:
        logger.info("Training Logistic Regression member...")
        lr, lr_params, lr_score = train_lr_gridsearch(
            X, y, scoring=scoring, cv=cv, n_jobs=n_jobs,
        )
        classifiers["lr"] = lr
        member_params["lr"] = lr_params
        member_scores["lr"] = lr_score

    if "cnb" in members:
        logger.info("Training ComplementNB member...")
        cnb = train_cnb(X, y)
        classifiers["cnb"] = cnb
        member_params["cnb"] = {"alpha": 1.0}
        member_scores["cnb"] = None  # no CV search

    ensemble = EnsembleClassifier(classifiers=classifiers)
    ensemble.calibrate(X)

    logger.info("Ensemble built with members: %s", list(classifiers.keys()))
    return ensemble, member_params, member_scores
