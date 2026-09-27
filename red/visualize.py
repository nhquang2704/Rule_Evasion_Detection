"""Visualization: Precision-Recall-Threshold plots and Rule Attribution plots.

Generates publication-quality figures:
  - plot_pr_threshold(): Metrics vs. threshold (Figure 3 in AMIDES paper)
  - plot_attribution():  Distribution + CDF of rule attribution ranks (Figure 4)
"""

import numpy as np
import matplotlib.pyplot as plt


plt.style.use("seaborn-v0_8-colorblind")
COLORS = plt.rcParams["axes.prop_cycle"].by_key()["color"]


# ---------------------------------------------------------------------------
# Precision-Recall-Threshold plot
# ---------------------------------------------------------------------------

def plot_pr_threshold(
    evaluations: list,
    labels: list = None,
    output_path: str = None,
    title: str = "Misuse Classification",
):
    """Plot Precision, Recall, F1, MCC vs. threshold for one or more evaluations.

    Parameters
    ----------
    evaluations : list of BinaryEvaluation
        Each evaluation contains thresholds and metric arrays.
    labels : list of str, optional
        Legend labels for each evaluation.
    output_path : str, optional
        If given, save figure to this path (PDF/PNG).
    title : str
        Figure title.
    """
    if labels is None:
        labels = [f"Model {i}" for i in range(len(evaluations))]

    fig, axes = plt.subplots(2, 2, figsize=(12, 8), sharex=True)
    metric_names = ["Precision", "Recall", "F1-Score", "MCC"]
    metric_attrs = ["precision", "recall", "f1_scores", "mccs"]

    for ax, mname, mattr in zip(axes.flat, metric_names, metric_attrs):
        for i, (ev, label) in enumerate(zip(evaluations, labels)):
            thresholds = ev.thresholds
            values = getattr(ev, mattr)
            linestyle = ["-", "--", "-.", ":"][i % 4]
            ax.plot(thresholds, values, linestyle=linestyle, color=COLORS[i % len(COLORS)], label=label)

            # Mark optimal threshold
            opt_idx = ev.optimal_threshold_idx()
            ax.axvline(x=thresholds[opt_idx], color=COLORS[i % len(COLORS)], alpha=0.3, linestyle=":")

        # Mark default threshold = 0.5
        ax.axvline(x=0.5, color="gray", alpha=0.5, linestyle="--", label="default (0.5)")

        ax.set_title(mname, fontsize=13)
        ax.set_ylabel(mname, fontsize=11)
        ax.set_xlim([0, 1])
        ax.set_ylim([0, 1.05])
        ax.grid(True, alpha=0.3)
        ax.legend(fontsize=9)

    axes[1, 0].set_xlabel("Threshold", fontsize=11)
    axes[1, 1].set_xlabel("Threshold", fontsize=11)

    fig.suptitle(title, fontsize=14, y=1.01)
    fig.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight", dpi=150)
        plt.close(fig)
    else:
        plt.show()


# ---------------------------------------------------------------------------
# Rule Attribution plot (Distribution + CDF)
# ---------------------------------------------------------------------------

def plot_attribution(
    top_n_hits: np.ndarray,
    output_path: str = None,
    title: str = "Rule Attribution",
):
    """Plot distribution and cumulative distribution of rule attribution ranks.

    Parameters
    ----------
    top_n_hits : np.ndarray
        Array of hit counts per rank position (0-indexed).
    output_path : str, optional
        Save path for the figure.
    title : str
        Figure title.
    """
    fig, ax = plt.subplots(figsize=(8, 4))

    data = np.array(top_n_hits)
    total = data.sum()
    if total == 0:
        plt.close(fig)
        return

    relative = data / total
    cumulative = np.cumsum(relative)
    x = np.arange(1, len(data) + 1)

    # Bar chart: distribution
    ax.bar(x, relative, color=COLORS[2], width=1.0, alpha=0.7, label="Distribution")

    # Line: cumulative
    ax.plot(x, cumulative, color=COLORS[0], linewidth=2, label="Cumulative")
    ax.fill_between(x, cumulative, alpha=0.1, color=COLORS[0])

    ax.set_xlim([0, len(data) + 1])
    ax.set_ylim([0, 1.05])
    ax.set_xlabel("Attribution rank of true evaded rule", fontsize=12)
    ax.set_ylabel("Share of true alerts", fontsize=12)
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)

    fig.suptitle(title, fontsize=13)
    fig.tight_layout()

    if output_path:
        fig.savefig(output_path, bbox_inches="tight", dpi=150)
        plt.close(fig)
    else:
        plt.show()
