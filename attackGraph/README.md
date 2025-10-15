# Attack Graph Generator

A sophisticated tool for generating interactive and static attack graphs from vulnerability scan data. This tool helps visualize potential attack paths through your network infrastructure.

## 🎯 Features

- **Interactive HTML Visualization**: Beautiful, interactive attack graphs using PyVis
- **Static Image Export**: High-quality SVG and PNG exports with legends
- **Attack Path Analysis**: Computes and ranks the most likely attack paths
- **Multiple Output Formats**: CSV, JSON, HTML, SVG, PNG
- **Customizable Scoring**: Considers CVSS scores, asset criticality, and path complexity

## 🚀 Quick Start

### Prerequisites

```bash
pip install -r requirements.txt
```

### Basic Usage

```bash
python attack_graph_generator.py
```

This will process the `sample_scan.json` file and generate all output formats.

## 📊 Input Data Format

The tool expects JSON data with vulnerability scan results:

```json
[
  {
    "asset_id": "asset-web-01",
    "asset_type": "web_server",
    "ip": "10.0.1.10",
    "service": "apache",
    "port": 80,
    "cve_id": "CVE-2024-1234",
    "cvss": 9.8,
    "description": "Remote code execution vulnerability",
    "exploit_available": true,
    "asset_criticality": 8,
    "connected_to": ["asset-app-01", "asset-db-01"]
  }
]
```

### Required Fields
- `asset_id`: Unique identifier for the asset
- `asset_type`: Type of asset (web_server, db_server, etc.)
- `ip`: IP address of the asset
- `cvss`: CVSS score of the vulnerability
- `asset_criticality`: Criticality rating (1-10)

### Optional Fields
- `cve_id`: CVE identifier
- `exploit_available`: Boolean indicating if exploit exists
- `connected_to`: Array of connected asset IDs
- `service`, `port`, `description`: Additional metadata

## 📈 Output Files

### 1. Interactive HTML (`attack_graph_beautiful.html`)
- Interactive network visualization
- Hover tooltips with detailed information
- Physics-based layout with smooth animations
- Clickable nodes and edges

### 2. Static Images
- **SVG** (`attack_graph_beautiful.svg`): Vector format, scalable
- **PNG** (`attack_graph_beautiful.png`): Raster format, high resolution

### 3. Attack Paths (`top_attack_paths.csv`)
```csv
rank,source,target,path,score,path_length
1,asset-internet-gw,asset-db-01,asset-internet-gw -> asset-web-01 -> asset-db-01,0.0077,3
```

### 4. Graph Data (`attack_graph.json`)
Complete graph structure in JSON format for further processing.

## 🔧 Configuration

Edit the configuration section at the top of `attack_graph_generator.py`:

```python
# Input/Output Configuration
INPUT_FILE = "sample_scan.json"
OUT_HTML = "attack_graph_beautiful.html"
OUT_SVG = "attack_graph_beautiful.svg"
OUT_PNG = "attack_graph_beautiful.png"

# Analysis Parameters
MAX_PATH_DEPTH = 4      # Maximum attack path length
TOP_K_PATHS = 10        # Number of top paths to export
FIGSIZE = (14, 10)      # Static image size
```

## 🧮 Attack Path Scoring

The tool uses a sophisticated scoring algorithm that considers:

1. **CVSS Scores**: Higher vulnerability scores increase path likelihood
2. **Asset Criticality**: Paths to critical assets are prioritized
3. **Path Length**: Shorter paths are generally more likely
4. **Exploit Availability**: Paths through exploitable vulnerabilities score higher

**Formula**: `score = path_probability × (0.65 × target_criticality + 0.35 × length_penalty)`

## 🎨 Visualization Features

### Node Types
- **Assets**: Rectangular nodes, sized by criticality
  - 🔴 Red: Exploitable vulnerabilities present
  - 🟢 Green: No known exploits
- **Vulnerabilities**: Smaller rectangular nodes (gray)

### Edge Types
- **Orange**: `has_vulnerability` relationships
- **Blue**: `connected_to` relationships
- **Width**: Proportional to edge weight (CVSS score)

## 🧪 Testing

Run the test suite:

```bash
python test_attack_graph.py
```

This will:
- Validate input data loading
- Test graph construction
- Verify attack path computation
- Check output file generation

## 🔒 Security Considerations

- **No API Keys Required**: This tool works entirely offline
- **Local Processing**: All data stays on your system
- **Sample Data**: Includes realistic but fictional vulnerability data
- **Privacy**: No external network connections required

## 📋 Dependencies

- `networkx`: Graph analysis and algorithms
- `pandas`: Data manipulation and CSV export
- `pyvis`: Interactive network visualizations
- `matplotlib`: Static image generation

## 🛠️ Customization

### Adding New Asset Types
Modify the entry point and target detection logic:

```python
# Custom entry points
entry_points = [n for n, d in G.nodes(data=True) 
                if d.get("asset_type") == "your_entry_type"]

# Custom targets
targets = [n for n, d in G.nodes(data=True) 
           if d.get("asset_type") == "your_target_type"]
```

### Custom Scoring
Adjust the scoring function in `compute_attack_paths()`:

```python
# Custom score calculation
score = your_custom_formula(path_prob, target_crit, penalty)
```

## 🎯 Use Cases

- **Penetration Testing**: Visualize potential attack vectors
- **Risk Assessment**: Identify critical attack paths
- **Network Hardening**: Prioritize security improvements
- **Compliance Reporting**: Generate visual security assessments
- **Training**: Educational tool for cybersecurity concepts

## 🚀 Integration

The tool can be integrated into larger security platforms:
- Import scan results from Nessus, OpenVAS, Nmap
- Export results to SIEM systems
- Embed visualizations in security dashboards
- Automate report generation