"""
Inspection of feature lists, models, main.tex, risk bands, and moto.
"""
import os
import sys
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECT_ROOT = os.path.dirname(ROOT)
PYLIBS = os.path.join(PROJECT_ROOT, "pylibs")
if os.path.exists(PYLIBS) and PYLIBS not in sys.path:
    sys.path.insert(0, PYLIBS)

print("=" * 60)
print("1. FEATURE LISTS CONFIRMATION")
print("=" * 60)

files_to_check = [
    os.path.join(ROOT, "train_model.py"),
    os.path.join(ROOT, "engines", "feature_extractor.py"),
    os.path.join(ROOT, "engines", "ml_engine.py"),
    os.path.join(ROOT, "benchmark_models.py"),
    os.path.join(ROOT, "experiments", "run_e1_benchmarks.py"),
]

for p in files_to_check:
    print(f"\nFile: {os.path.relpath(p, PROJECT_ROOT)}")
    if not os.path.exists(p):
        print("  [NOT FOUND]")
        continue
    with open(p, "r", encoding="utf-8") as f:
        code = f.read()
    # Find FLOW_FEATURES or similar
    matches = re.findall(r"(?:FLOW_FEATURES|FEATURES|FEATURE_NAMES)\s*=\s*\[(.*?)\]", code, re.DOTALL)
    if matches:
        for m in matches:
            items = [x.strip().strip("'\"") for x in m.split(",") if x.strip() and not x.strip().startswith("#")]
            print("  Found features:", items)
    else:
        print("  No explicit FLOW_FEATURES list found via regex.")

print("\n" + "=" * 60)
print("2. ML ENGINE ENSEMBLE / FUSION LOGIC")
print("=" * 60)
ml_engine_path = os.path.join(ROOT, "engines", "ml_engine.py")
if os.path.exists(ml_engine_path):
    with open(ml_engine_path, "r", encoding="utf-8") as f:
        ml_code = f.read()
    # Check for fusion, ensemble, predict, threshold, max
    for func in ["score", "predict", "detect", "ensemble", "fuse", "normalize"]:
        matches = re.findall(rf"def\s+({func}\w*)\s*\(.*?\):", ml_code)
        if matches:
            print("  Functions matching:", matches)
    # Search for max or average fusion
    fusion_lines = [line.strip() for line in ml_code.split("\n") if any(k in line.lower() for k in ["max(", "average", "fusion", "threshold", "ensemble"])]
    print(f"  Sample ensemble lines ({len(fusion_lines)} matches):")
    for l in fusion_lines[:15]:
        print("   ", l)

print("\n" + "=" * 60)
print("3. TEX FILES: main.tex vs ram_antivirus_ieee_paper.tex")
print("=" * 60)
tex1 = os.path.join(PROJECT_ROOT, "docs", "research_paper", "main.tex")
tex2 = os.path.join(PROJECT_ROOT, "ram_antivirus_ieee_paper.tex")
for t in [tex1, tex2]:
    print(f"\nFile: {os.path.relpath(t, PROJECT_ROOT)}")
    if os.path.exists(t):
        with open(t, "r", encoding="utf-8") as f:
            t_content = f.read()
        print(f"  Length: {len(t_content):,} chars, {t_content.count(chr(10))} lines")
        has_table4 = "Table IV" in t_content or "table*}" in t_content or "Detector" in t_content
        has_fig5 = "Figure 5" in t_content or "fig:roc" in t_content or "fig5" in t_content.lower()
        print(f"  Contains Table IV / benchmark table: {has_table4}")
        print(f"  Contains Figure 5 / ROC figure: {has_fig5}")
        # Look for table headers
        tables = re.findall(r"\\begin\{table\*?\}.*?\\end\{table\*?\}", t_content, re.DOTALL)
        print(f"  Number of LaTeX tables: {len(tables)}")
        for i, tbl in enumerate(tables):
            caption = re.search(r"\\caption\{(.*?)\}", tbl)
            print(f"    Table {i+1}: {caption.group(1) if caption else 'No caption'}")

print("\n" + "=" * 60)
print("4. RISK ENGINE BANDS (30/60/80 vs 26/51/76)")
print("=" * 60)
risk_engine_path = os.path.join(ROOT, "engines", "risk_engine.py")
if os.path.exists(risk_engine_path):
    with open(risk_engine_path, "r", encoding="utf-8") as f:
        r_code = f.read()
    # Find _risk_level or bands
    m = re.search(r"def _risk_level\(.*?\):.*?(?=def |\Z)", r_code, re.DOTALL)
    if m:
        print("  _risk_level in risk_engine.py:")
        print("   ", "\n    ".join(m.group(0).split("\n")[:15]))

print("\n" + "=" * 60)
print("5. MOTO / BOTO3 CHECK FOR E6")
print("=" * 60)
try:
    import boto3
    print("  boto3 is INSTALLED:", boto3.__version__)
except ImportError:
    print("  boto3 is NOT INSTALLED")

try:
    import moto
    print("  moto is INSTALLED:", getattr(moto, "__version__", "installed"))
except ImportError:
    print("  moto is NOT INSTALLED")

