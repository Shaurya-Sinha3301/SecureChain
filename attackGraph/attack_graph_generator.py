"""
attack_graph_beautiful.py

Polished Attack Graph generator:
 - Interactive HTML (PyVis) with beautiful style & tooltips
 - Static SVG + PNG with rounded rectangular nodes and legend
 - Exports: top_attack_paths.csv, attack_graph.json

Usage:
    pip install networkx pyvis pandas matplotlib
    python attack_graph_beautiful.py

Config at the top of the file.
"""

import json
import os
from math import sqrt
from typing import List, Dict, Any

import networkx as nx
import pandas as pd
from pyvis.network import Network
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Patch
from matplotlib.collections import PatchCollection

# ------------------ CONFIG ------------------
INPUT_FILE = "sample_scan.json"
OUT_HTML = "attack_graph_beautiful.html"
OUT_SVG = "attack_graph_beautiful.svg"
OUT_PNG = "attack_graph_beautiful.png"
OUT_PATHS_CSV = "top_attack_paths.csv"
OUT_GRAPH_JSON = "attack_graph.json"

MAX_PATH_DEPTH = 4
TOP_K_PATHS = 10
FIGSIZE = (14, 10)
# --------------------------------------------

# ---------- Utilities ----------
def load_scan(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Input file '{path}' not found.")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(obj, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    print(f"Saved JSON to {path}")


# ---------- Graph Construction ----------
def build_graph(records: List[Dict[str, Any]]) -> nx.DiGraph:
    G = nx.DiGraph()

    for r in records:
        asset = r["asset_id"]
        asset_label = f"{r.get('asset_type','asset')}\n{r.get('ip','')}"
        critical = float(r.get("asset_criticality", 5))
        exploitable = bool(r.get("exploit_available", False))
        color = "#D32F2F" if exploitable else "#2E7D32"  # red or green
        G.add_node(asset, node_type="asset", label=asset_label, raw_label=asset, criticality=critical,
                   exploit_available=exploitable, ip=r.get("ip", ""), color=color)

        # Vulnerability node id prefers cve_id else vuln_id
        vuln_node = r.get("cve_id") or r.get("vuln_id") or f"{asset}_vuln"
        vuln_label = f"{vuln_node}\nCVSS {r.get('cvss', '')}"
        if not G.has_node(vuln_node):
            G.add_node(vuln_node, node_type="vuln", label=vuln_label, cvss=float(r.get("cvss", 0)),
                       color="#9E9E9E")

        G.add_edge(asset, vuln_node, relation="has_vulnerability", weight=float(r.get("cvss", 0)))

    # Add connectivity edges: use explicit connected_to if present else /24 heuristic
    assets_by_ip = {r["asset_id"]: r["ip"] for r in records}
    for r in records:
        src = r["asset_id"]
        conns = r.get("connected_to", [])
        if not conns:
            # /24 heuristic
            prefix = ".".join(r.get("ip", "").split(".")[:3])
            conns = [aid for aid, ip in assets_by_ip.items() if aid != src and ip.startswith(prefix)]
        for tgt in conns:
            if tgt in G.nodes and not G.has_edge(src, tgt):
                G.add_edge(src, tgt, relation="connected_to", weight=1.0)

    return G


# ---------- Attack Path Computation ----------
def compute_attack_paths(G: nx.DiGraph, entry_points: List[str], targets: List[str],
                         max_depth: int = 4, top_k: int = 10) -> List[Dict[str, Any]]:
    paths = []
    for src in entry_points:
        for tgt in targets:
            try:
                for path in nx.all_simple_paths(G, source=src, target=tgt, cutoff=max_depth):
                    # compute edge normalized weights (cvss->0..1)
                    edge_norms = []
                    for u, v in zip(path[:-1], path[1:]):
                        w = G[u][v].get("weight", 1.0)
                        norm = min(1.0, max(0.01, float(w) / 10.0))
                        edge_norms.append(norm)
                    path_prob = 1.0
                    for p in edge_norms:
                        path_prob *= p
                    target_crit = G.nodes[path[-1]].get("criticality", 5) / 10.0 if G.nodes[path[-1]].get(
                        "node_type") == "asset" else 0.5
                    penalty = 1.0 / max(1, len(path))
                    score = path_prob * (0.65 * target_crit + 0.35 * penalty)
                    paths.append({"source": src, "target": tgt, "path": path, "score": score, "len": len(path)})
            except nx.NetworkXNoPath:
                pass
    paths = sorted(paths, key=lambda x: -x["score"])[:top_k]
    return paths


# ---------- Exports ----------
def export_top_paths(paths: List[Dict[str, Any]], path_csv: str):
    rows = []
    for i, p in enumerate(paths, 1):
        rows.append({
            "rank": i,
            "source": p["source"],
            "target": p["target"],
            "path": " -> ".join(p["path"]),
            "score": p["score"],
            "path_length": p["len"]
        })
    df = pd.DataFrame(rows)
    df.to_csv(path_csv, index=False)
    print(f"Saved top paths CSV to {path_csv}")


def export_graph_json(G: nx.DiGraph, out_json: str):
    j = {"nodes": [], "edges": []}
    for n, d in G.nodes(data=True):
        j["nodes"].append({"id": n, **d})
    for u, v, d in G.edges(data=True):
        j["edges"].append({"source": u, "target": v, **d})
    save_json(j, out_json)


# ---------- Interactive HTML (pyvis) ----------
def create_interactive_html(G: nx.DiGraph, out_html: str, title: str = "Attack Graph"):
    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff", font_color="#222222")

    # Set physics + nice options for vis.js
    net.set_options("""
    var options = {
      "nodes": {
        "borderWidth": 1,
        "font": {"size": 14, "face": "Arial"},
        "shapeProperties": {"borderRadius": 8}
      },
      "edges": {
        "color": {"inherit": true},
        "smooth": {"enabled": true, "type": "cubicBezier"}
      },
      "physics": {
        "barnesHut": {
          "gravitationalConstant": -16000,
          "centralGravity": 0.3,
          "springLength": 200,
          "springConstant": 0.05,
          "damping": 0.09
        },
        "minVelocity": 0.75
      }
    }
    """)

    # Add nodes (size by criticality for assets, smaller for vuln)
    for n, d in G.nodes(data=True):
        label = d.get("label", n)
        node_type = d.get("node_type", "asset")
        if node_type == "asset":
            crit = float(d.get("criticality", 5))
            size = 18 + (crit / 10.0) * 30  # 18..48
            title = f"<b>{d.get('raw_label', n)}</b><br>Type: {d.get('asset_type','') or ''}<br>IP: {d.get('ip','')}<br>Criticality: {crit}<br>Exploit available: {d.get('exploit_available')}"
            shape = "box"
        else:
            size = 14
            title = f"<b>{label}</b><br>CVSS: {d.get('cvss', '')}"
            shape = "box"
        net.add_node(n, label=label, title=title, color=d.get("color", "#1f78b4"), shape=shape, size=size)

    # Add edges (thickness by weight)
    for u, v, d in G.edges(data=True):
        rel = d.get("relation", "")
        w = d.get("weight", 1.0)
        width = 1 + (w / 10.0) * 4  # 1..5
        color = "#FFB74D" if rel == "has_vulnerability" else "#64B5F6"
        net.add_edge(u, v, label=rel, title=f"{rel} (w={w})", color=color, width=width, arrows="to")

    net.heading = title
    # net.show_buttons(filter_=['nodes', 'physics'])  # <- remove or comment out
    net.write_html(out_html)
    print(f"Interactive HTML written to {out_html}")

    

# ---------- Static SVG/PNG drawing ----------
def draw_static_graph(G: nx.DiGraph, out_svg: str, out_png: str, figsize=(14, 10)):
    plt.figure(figsize=figsize)
    ax = plt.gca()
    ax.set_facecolor("white")
    pos = nx.spring_layout(G, seed=42, k=0.6)

    # We'll create rounded rectangles (FancyBboxPatch) for nodes
    node_patches = []
    node_texts = []
    arrow_patches = []

    # Determine node sizes in figure coordinates
    # Convert positions to plot coords (they are already data coords)
    for n, d in G.nodes(data=True):
        x, y = pos[n]
        node_type = d.get("node_type", "asset")
        if node_type == "asset":
            crit = float(d.get("criticality", 5))
            width = 0.18 + (crit / 10.0) * 0.30  # width relative to axes
            height = 0.08 + (crit / 10.0) * 0.12
            facecolor = d.get("color", "#4CAF50")
        else:
            width = 0.16
            height = 0.06
            facecolor = d.get("color", "#9E9E9E")

        # Create a rounded rect centered on (x,y)
        bbox = FancyBboxPatch((x - width / 2, y - height / 2),
                              width, height,
                              boxstyle="round,pad=0.02,rounding_size=0.02",
                              linewidth=1.0, facecolor=facecolor, edgecolor="#333333", alpha=0.95)
        ax.add_patch(bbox)
        node_patches.append(bbox)
        # Add label text
        label = d.get("label", n).replace("\n", "  ")
        ax.text(x, y, label, ha="center", va="center", fontsize=8, color="#ffffff" if node_type == "asset" and d.get("exploit_available") else "#000000")

    # Draw edges with arrows and variable width
    for u, v, d in G.edges(data=True):
        x1, y1 = pos[u]
        x2, y2 = pos[v]
        rel = d.get("relation", "")
        w = d.get("weight", 1.0)
        lw = 0.6 + (w / 10.0) * 2.5
        color = "#E65100" if rel == "has_vulnerability" else "#1976D2"

        # create arrow patch
        arrow = FancyArrowPatch((x1, y1), (x2, y2),
                                arrowstyle='-|>', mutation_scale=12,
                                linewidth=lw, color=color, alpha=0.9)
        ax.add_patch(arrow)

        # edge label (midpoint)
        mx, my = (x1 + x2) / 2, (y1 + y2) / 2
        ax.text(mx, my, rel, fontsize=7, color="#333333", ha="center", va="center", bbox=dict(facecolor="white", alpha=0.6, boxstyle="round,pad=0.1", lw=0))

    # Legend
    legend_elems = [
        Patch(facecolor="#D32F2F", edgecolor="#333", label="Asset (exploit available)"),
        Patch(facecolor="#2E7D32", edgecolor="#333", label="Asset (no exploit)"),
        Patch(facecolor="#9E9E9E", edgecolor="#333", label="Vulnerability"),
        Patch(facecolor="#E65100", edgecolor="#333", label="has_vulnerability edge"),
        Patch(facecolor="#1976D2", edgecolor="#333", label="connected_to edge")
    ]
    ax.legend(handles=legend_elems, loc="upper right", frameon=True)

    ax.set_xticks([])
    ax.set_yticks([])
    ax.set_title("Attack Graph (Static View)", fontsize=16)
    plt.tight_layout()

    # Save SVG and PNG
    plt.savefig(out_svg, format="svg", dpi=300)
    plt.savefig(out_png, format="png", dpi=200)
    plt.close()
    print(f"Saved static SVG to {out_svg} and PNG to {out_png}")


# ---------- Main ----------
def main():
    print("Loading scan data...")
    records = load_scan(INPUT_FILE)

    print("Building graph...")
    G = build_graph(records)
    print(f"Graph built: {len(G.nodes())} nodes, {len(G.edges())} edges")

    # Identify entry points (prefer internet gateway or web_server)
    entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                    (d.get("asset_type") == "internet_gateway" or "web_server" in (d.get("asset_type") or ""))]
    if not entry_points:
        # Fallback: any asset with external IP or web service
        entry_points = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and
                       (not d.get("ip", "").startswith("10.") or "web" in (d.get("asset_type") or ""))]
    # targets: DBs
    targets = [n for n, d in G.nodes(data=True) if d.get("node_type") == "asset" and "db_server" in (d.get("asset_type") or "")]
    if not targets:
        # fallback to highest criticality assets
        assets = [(n, d.get("criticality", 5)) for n, d in G.nodes(data=True) if d.get("node_type") == "asset"]
        assets = sorted(assets, key=lambda x: -x[1])
        targets = [assets[0][0]] if assets else []

    print("Entry points:", entry_points)
    print("Targets:", targets)

    print("Computing top attack paths...")
    paths = compute_attack_paths(G, entry_points, targets, max_depth=MAX_PATH_DEPTH, top_k=TOP_K_PATHS)
    export_top_paths(paths, OUT_PATHS_CSV)
    export_graph_json(G, OUT_GRAPH_JSON)

    print("Creating interactive HTML...")
    create_interactive_html(G, OUT_HTML)

    print("Drawing static images (SVG/PNG)...")
    draw_static_graph(G, OUT_SVG, OUT_PNG, figsize=FIGSIZE)

    print("\nAll done! Outputs:")
    print(" - Interactive HTML:", OUT_HTML)
    print(" - Static SVG:", OUT_SVG)
    print(" - Static PNG:", OUT_PNG)
    print(" - Top paths CSV:", OUT_PATHS_CSV)
    print(" - Full graph JSON:", OUT_GRAPH_JSON)


if __name__ == "__main__":
    main()
