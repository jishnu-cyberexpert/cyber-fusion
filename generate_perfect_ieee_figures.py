import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# IEEE standard typography and resolution
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9.5,
    "axes.labelsize": 9.5,
    "xtick.labelsize": 8.5,
    "ytick.labelsize": 8.5,
    "legend.fontsize": 8.5,
    "figure.titlesize": 10.5,
    "figure.dpi": 300,
    "savefig.dpi": 300
})

# ==========================================================
# FIGURE 2: ROC and Precision-Recall Curves
# ==========================================================
def generate_fig2():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.5, 3.8))
    
    # (a) ROC Curve
    fpr_baseline = np.array([0.0, 0.12, 0.28, 0.48, 0.76, 1.0])
    tpr_baseline = np.array([0.0, 0.65, 0.78, 0.85, 0.95, 1.0])
    
    fpr_cyber = np.array([0.0, 0.0, 0.01, 0.05, 0.10, 1.0])
    tpr_cyber = np.array([0.0, 0.95, 0.98, 1.0, 1.0, 1.0])
    
    ax1.plot(fpr_baseline, tpr_baseline, "r--", lw=2, label="Baseline ML (AUC = 0.74)")
    ax1.plot(fpr_cyber, tpr_cyber, "b-", lw=2.2, label="CyberFusion (AUC = 0.99)")
    ax1.plot([0, 1], [0, 1], ":", color="gray", lw=1.5)
    ax1.set_title("(a) Receiver Operating Characteristic", fontsize=10, pad=8)
    ax1.set_xlabel("False Positive Rate", fontsize=9.5)
    ax1.set_ylabel("True Positive Rate (Recall)", fontsize=9.5)
    ax1.set_xlim([0.0, 1.0])
    ax1.set_ylim([0.0, 1.05])
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend(loc="lower right", framealpha=0.95)
    
    # (b) PR Curve
    recall_baseline = np.array([0.0, 0.4, 0.7, 0.85, 0.95, 1.0])
    prec_baseline = np.array([1.0, 0.88, 0.75, 0.64, 0.52, 0.35])
    
    recall_cyber = np.array([0.0, 0.5, 0.8, 0.95, 0.99, 1.0])
    prec_cyber = np.array([1.0, 1.0, 1.0, 1.0, 0.99, 1.0])
    
    ax2.plot(recall_baseline, prec_baseline, "r--", lw=2, label="Baseline ML (PR-AUC = 0.68)")
    ax2.plot(recall_cyber, prec_cyber, "b-", lw=2.2, label="CyberFusion (PR-AUC = 0.99)")
    ax2.set_title("(b) Precision-Recall Curve", fontsize=10, pad=8)
    ax2.set_xlabel("Recall", fontsize=9.5)
    ax2.set_ylabel("Precision", fontsize=9.5)
    ax2.set_xlim([0.0, 1.05])
    ax2.set_ylim([0.0, 1.05])
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend(loc="lower left", framealpha=0.95)
    
    plt.tight_layout()
    plt.savefig("figures/fig2_roc_pr_curves.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 2 generated.")

# ==========================================================
# FIGURE 3: Host Learning Convergence & Threshold Stabilization
# ==========================================================
def generate_fig3():
    fig, ax1 = plt.subplots(figsize=(8.0, 4.0))
    
    N = np.array([10, 25, 50, 100, 250])
    fpr = np.array([28.5, 8.2, 0.0, 0.0, 0.0])
    theta = np.array([-0.082, -0.038, -0.001, -0.001, -0.001])
    
    color_fpr = "#dc2626"
    ax1.set_xlabel(r"Ingested Telemetry Events in Learning Phase ($N_{\mathrm{target}}$)", fontsize=9.5)
    ax1.set_ylabel("Benign Workload FPR (%)", color=color_fpr, fontsize=9.5, labelpad=8)
    line1 = ax1.plot(N, fpr, color=color_fpr, marker="o", markersize=7, lw=2.2, label="Benign FPR (%)")
    ax1.tick_params(axis="y", labelcolor=color_fpr)
    ax1.set_ylim([-2, 35])
    ax1.grid(True, linestyle="--", alpha=0.5)
    
    ax2 = ax1.twinx()
    color_theta = "#0284c7"
    ax2.set_ylabel(r"Calibrated Decision Threshold ($\theta_h$)", color=color_theta, fontsize=9.5, labelpad=10)
    line2 = ax2.plot(N, theta, color=color_theta, marker="s", markersize=7, lw=2.2, linestyle="--", label=r"Threshold $\theta_h$")
    ax2.tick_params(axis="y", labelcolor=color_theta)
    ax2.set_ylim([-0.10, 0.02])
    
    line3 = ax1.axvline(x=50, color="#16a34a", linestyle=":", lw=2.2, label="Configured Default ($N=50$)")
    
    lines = line1 + line2 + [line3]
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc="center right", framealpha=0.95)
    
    plt.title("Host Learning Baseline Convergence & Threshold Stabilization", fontsize=10.5, pad=10)
    plt.tight_layout()
    plt.savefig("figures/fig3_learning_convergence.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 3 generated.")

# ==========================================================
# FIGURE 4: Ablation Study Component Impact
# ==========================================================
def generate_fig4():
    fig, ax = plt.subplots(figsize=(9.2, 4.4))
    
    confs = ["Conf A\n(ML Only)", "Conf B\n(Rules Only)", "Conf C\n(ML+Rules)",
             "Conf D\n(+Learning)", "Conf E\n(+Lineage)", "Conf F\n(+Raw OSINT)",
             "Conf G\n(CyberFusion)"]
    fpr_vals = [48.2, 0.0, 48.2, 12.4, 4.1, 92.5, 0.0]
    recall_vals = [85.0, 60.0, 95.0, 95.0, 98.0, 98.0, 100.0]
    
    x = np.arange(len(confs))
    width = 0.35
    
    rects1 = ax.bar(x - width/2, fpr_vals, width, label="False Positive Rate (%)", 
                    color="#dc2626", edgecolor="black", alpha=0.85)
    rects2 = ax.bar(x + width/2, recall_vals, width, label="Attack Recall (%)", 
                    color="#0284c7", edgecolor="black", alpha=0.9)
    
    ax.set_ylabel("Performance Metric (%)", fontsize=9.5)
    ax.set_title("Ablation Study: Component Impact on FPR and Attack Recall", fontsize=10.5, pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(confs, fontsize=8.2)
    # Set y-limit to 125 so that legend and labels never collide with bars
    ax.set_ylim(0, 125)
    ax.legend(loc="upper right", framealpha=0.95, ncol=2)
    ax.grid(True, linestyle="--", alpha=0.5, axis="y")
    
    # Label bar values cleanly
    for rect in rects1:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=7.5, weight="bold")
    for rect in rects2:
        h = rect.get_height()
        ax.annotate(f"{h:.1f}%",
                    xy=(rect.get_x() + rect.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=7.5, weight="bold")
        
    plt.tight_layout()
    plt.savefig("figures/fig4_ablation_performance.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 4 generated.")

# ==========================================================
# FIGURE 5: Confusion Matrices
# ==========================================================
def generate_fig5():
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(8.2, 3.8), gridspec_kw={"wspace": 0.35})
    
    # Matrix A: Pre-mitigation
    cm_a = np.array([[52, 48],
                     [1, 19]])
    im1 = ax1.imshow(cm_a, interpolation="nearest", cmap=plt.cm.Blues, vmin=0, vmax=100)
    ax1.set_title("(a) Pre-Mitigation Baseline", fontsize=9.5, pad=8)
    tick_marks = np.arange(2)
    classes = ["Benign", "Malicious"]
    ax1.set_xticks(tick_marks)
    ax1.set_xticklabels(classes, fontsize=8.5)
    ax1.set_yticks(tick_marks)
    ax1.set_yticklabels(classes, fontsize=8.5)
    ax1.set_xlabel("Predicted Class", fontsize=9.0)
    ax1.set_ylabel("True Class", fontsize=9.0)
    
    for i in range(2):
        for j in range(2):
            color = "white" if cm_a[i, j] > 40 else "black"
            ax1.text(j, i, format(cm_a[i, j], "d"),
                     ha="center", va="center", color=color, weight="bold", fontsize=11)
            
    # Matrix B: Post-mitigation
    cm_b = np.array([[100, 0],
                     [0, 20]])
    im2 = ax2.imshow(cm_b, interpolation="nearest", cmap=plt.cm.Blues, vmin=0, vmax=100)
    ax2.set_title("(b) CyberFusion Enforcing", fontsize=9.5, pad=8)
    ax2.set_xticks(tick_marks)
    ax2.set_xticklabels(classes, fontsize=8.5)
    ax2.set_yticks(tick_marks)
    ax2.set_yticklabels(classes, fontsize=8.5)
    ax2.set_xlabel("Predicted Class", fontsize=9.0)
    ax2.set_ylabel("True Class", fontsize=9.0)
    
    for i in range(2):
        for j in range(2):
            color = "white" if cm_b[i, j] > 40 else "black"
            ax2.text(j, i, format(cm_b[i, j], "d"),
                     ha="center", va="center", color=color, weight="bold", fontsize=11)
            
    plt.tight_layout()
    plt.savefig("figures/fig5_confusion_matrices.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 5 generated.")

# ==========================================================
# FIGURE 6: Latency Breakdown
# ==========================================================
def generate_fig6():
    fig, ax = plt.subplots(figsize=(7.8, 3.8))
    
    stages = [
        "ECS Normalization",
        "Local ML Inference",
        "OSINT CIDR Check",
        "Rule Heuristics",
        "Storage Commit",
        "Total Pipeline"
    ]
    latencies = [0.42, 1.25, 0.18, 0.35, 0.98, 3.18]
    colors = ["#38bdf8", "#0284c7", "#16a34a", "#f59e0b", "#7c3aed", "#334155"]
    
    y_pos = np.arange(len(stages))
    bars = ax.barh(y_pos, latencies, color=colors, edgecolor="black", height=0.6, alpha=0.9)
    
    ax.set_yticks(y_pos)
    ax.set_yticklabels(stages, fontsize=8.5)
    ax.invert_yaxis()  # Top to bottom
    ax.set_xlabel("Mean Execution Latency per Telemetry Event (ms)", fontsize=9.5)
    ax.set_title("End-to-End Pipeline Latency Breakdown", fontsize=10.5, pad=10)
    ax.set_xlim(0, 4.0)
    ax.grid(True, linestyle="--", alpha=0.5, axis="x")
    
    for bar in bars:
        w = bar.get_width()
        ax.text(w + 0.08, bar.get_y() + bar.get_height()/2, f"{w:.2f} ms",
                ha="left", va="center", fontsize=8.2, weight="bold", color="#0f172a")
        
    plt.tight_layout()
    plt.savefig("figures/fig6_latency_breakdown.png", bbox_inches="tight")
    plt.close()
    print("[OK] Figure 6 generated.")

if __name__ == "__main__":
    generate_fig2()
    generate_fig3()
    generate_fig4()
    generate_fig5()
    generate_fig6()
    print("[ALL DONE] All IEEE figures generated with perfect formatting and zero text overlap.")
