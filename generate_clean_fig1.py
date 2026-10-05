import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# IEEE publication settings
plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9.5,
    "figure.dpi": 300,
    "savefig.dpi": 300
})

# 12.8 x 6.4 inches canvas for zero text overlap and maximum readability
fig, ax = plt.subplots(figsize=(12.8, 6.4))
ax.set_xlim(0, 132)
ax.set_ylim(0, 66)
ax.axis("off")

def draw_card(x, y, w, h, title, lines, header_bg="#1565c0", body_bg="#f8fafc", border="#90caf9"):
    # Main card container
    card = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.5",
                          facecolor=body_bg, edgecolor=border, linewidth=1.3)
    ax.add_patch(card)
    
    # Title header banner
    header_h = 3.8
    header = FancyBboxPatch((x, y + h - header_h), w, header_h, boxstyle="round,pad=0.3",
                            facecolor=header_bg, edgecolor=header_bg, linewidth=0)
    ax.add_patch(header)
    ax.text(x + w / 2, y + h - header_h / 2, title,
            ha="center", va="center", color="white", weight="bold", fontsize=8.8)
    
    # Body text lines: left-aligned with proper margin to guarantee zero horizontal overflow
    n_lines = len(lines)
    avail_h = h - header_h - 1.0
    step = avail_h / (n_lines + 1)
    for i, line in enumerate(lines):
        line_y = y + h - header_h - 0.5 - (i + 1) * step
        ax.text(x + 1.5, line_y, line,
                ha="left", va="center", color="#1e293b", fontsize=7.8)

def draw_connector(x1, y1, x2, y2, label=None, label_pos=0.5, offset=2.2):
    ax.annotate("", xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle="-|>", color="#334155", lw=1.5,
                                mutation_scale=12))
    if label:
        lx = x1 + (x2 - x1) * label_pos
        ly = y1 + (y2 - y1) * label_pos + offset
        ax.text(lx, ly, label,
                ha="center", va="center", fontsize=7.4, color="#0f172a",
                weight="bold", style="italic",
                bbox=dict(boxstyle="round,pad=0.3", facecolor="#ffffff", edgecolor="#cbd5e1", lw=0.9))

# ==========================================================
# TIER 1: ENDPOINT SENSOR TIER (Agent)
# Coordinates: x=3 to x=33 (width=30)
# ==========================================================
tier1_bg = FancyBboxPatch((3, 2), 30, 60, boxstyle="round,pad=0.8",
                          facecolor="#f1f5f9", edgecolor="#64748b", lw=1.3, linestyle="--")
ax.add_patch(tier1_bg)
ax.text(18, 59.5, "TIER 1: ENDPOINT SENSOR",
        ha="center", va="center", weight="bold", fontsize=9.6, color="#1e293b")
ax.text(18, 57.0, "(Telemetry & Heuristics Agent)",
        ha="center", va="center", style="italic", fontsize=8.0, color="#475569")

draw_card(5, 41, 26, 13, "Raw Telemetry Collectors",
          ["• Process execution & args capture",
           "• TCP/UDP socket telemetry",
           "• SHA-256 binary hashing (psutil)"],
          header_bg="#0284c7", body_bg="#f0f9ff", border="#38bdf8")

draw_card(5, 23, 26, 13, "Relevance & Noise Filter",
          ["• Kernel & loopback suppression",
           "• Parent-child lineage tracking",
           "• Edge event deduplication (4s)"],
          header_bg="#059669", body_bg="#f0fdf4", border="#34d399")

draw_card(5, 5, 26, 13, "Edge Heuristics & OSINT",
          ["• Shannon entropy: H(S) >= 4.6",
           "• Verified CDN CIDR allowlist",
           "• Abuse.ch Feodo Tracker feed"],
          header_bg="#d97706", body_bg="#fffbeb", border="#fbbf24")

# Intra-Tier 1 flow
draw_connector(18, 41, 18, 36)
draw_connector(18, 23, 18, 18)

# ==========================================================
# INTER-TIER INGESTION BRIDGE (Clear 18-unit channel)
# Telemetry flows from Tier 1 right border (x=33) to Tier 2 left border (x=51)
# ==========================================================
draw_connector(33, 47.5, 51, 47.5, 
               label="HTTP/2 POST Ingest\n(4s JSON batch)", 
               label_pos=0.5, offset=2.5)

# ==========================================================
# TIER 2: CENTRAL ANALYTICS PLANE (FastAPI Backend)
# Coordinates: x=51 to x=129 (width=78)
# ==========================================================
tier2_bg = FancyBboxPatch((51, 2), 78, 60, boxstyle="round,pad=0.8",
                          facecolor="#f8fafc", edgecolor="#3b82f6", lw=1.4, linestyle="-")
ax.add_patch(tier2_bg)
ax.text(90, 59.2, "TIER 2: CENTRAL ANALYTICS & CORRELATION PLANE (FastAPI Backend)",
        ha="center", va="center", weight="bold", fontsize=9.6, color="#1e3a8a")

# Column 1 of Tier 2: Normalization & Baselining (x=53.5, w=35)
draw_card(53.5, 41, 35, 13, "Telemetry Normalizer",
          ["• Elastic Common Schema (ECS) mapping",
           "• Argument sanitization & normalization",
           "• Host & process attribution tagging"],
          header_bg="#2563eb", body_bg="#eff6ff", border="#93c5fd")

draw_card(53.5, 23, 35, 13, "Host Learning Profile",
          ["• State machine: LEARNING -> ENFORCING",
           "• Calibration threshold: N >= 50 events",
           "• Decision boundary: θ_h = P_2.0 baseline"],
          header_bg="#7c3aed", body_bg="#f5f3ff", border="#c4b5fd")

draw_card(53.5, 5, 35, 13, "Local ML Threat Inference",
          ["• Isolation Forest ensemble (T=50 trees)",
           "• Process lineage check: (Parent -> Child)",
           "• Unified risk score: R(x) ∈ [0, 100]"],
          header_bg="#db2777", body_bg="#fdf2f8", border="#f472b6")

# Intra-Column 1 vertical flow
draw_connector(71, 41, 71, 36)
draw_connector(71, 23, 71, 18)

# Column 2 of Tier 2: Detection, Correlation & Persistence (x=91.5, w=35)
draw_card(91.5, 41, 35, 13, "Detection Engine & Sigma",
          ["• MITRE ATT&CK production Sigma rules",
           "• Credential dump detection (LSASS / T1003)",
           "• Encoded PowerShell detection (T1059.001)"],
          header_bg="#b45309", body_bg="#fef3c7", border="#fcd34d")

draw_card(91.5, 23, 35, 13, "Cross-Domain XDR Correlator",
          ["• Multi-signal entity graph correlation",
           "• Threat intelligence enrichment (TIP/OSINT)",
           "• Incident synthesis & automated triage"],
          header_bg="#4338ca", body_bg="#eef2ff", border="#a5b4fc")

draw_card(91.5, 5, 35, 13, "Persistence & SOC Streamer",
          ["• Relational SQLite plane (alerts & incidents)",
           "• MongoDB Atlas unstructured telemetry lake",
           "• WebSocket real-time broadcast to Vite UI"],
          header_bg="#047857", body_bg="#ecfdf5", border="#6ee7b7")

# Cross-column horizontal dataflow (Col 1 right edge x=88.5 to Col 2 left edge x=91.5)
draw_connector(88.5, 47.5, 91.5, 47.5)
draw_connector(88.5, 29.5, 91.5, 29.5)
draw_connector(88.5, 11.5, 91.5, 11.5)

# Intra-Column 2 vertical flow
draw_connector(109, 41, 109, 36)
draw_connector(109, 23, 109, 18)

plt.tight_layout()
plt.savefig("figures/fig1_cyberfusion_architecture.png")
plt.close()
print("[OK] Figure 1 regenerated with clean layout and zero text overlap.")
