# Author: Vivek Sawant
# Date: 12-10-2026

from pathlib import Path

from ava.static.sink_rules import SMALI_RULES
from ava.static.sink_scanner import scan_smali_file

# Resolve to the actual decompiled root
decompiled_root = (
    Path.home()
    / "sample_apps"
    / "reversing_example"
    / "io.hextree.reversingexample_decompiled"
)

# decompiled_root = (
#     Path.home() / "sample_apps" / "bugbazaar" / "BugBazaar_v1.2.1_decompiled"
# )

smali_roots = sorted(decompiled_root.glob("smali*"))
print(f"Found {len(smali_roots)} Smali root directories.")

# Specify the target package scope explicitly
# target_package = "com.BugBazaar"
target_package = "io.hextree.reversingexample"
dummy_exported = {}
total_found = 0

for s_dir in smali_roots:
    for smali in s_dir.rglob("*.smali"):
        results = scan_smali_file(
            smali,
            SMALI_RULES,
            dummy_exported,
            app_package=target_package,
        )
        for r in results:
            print(
                f"[{r['rule_id']}] {r['class_name']}::{r['method_name']} (L{r['line_number']})"
            )
            print(f"   Snippet: {r['code_snippet']}")
            total_found += 1

print(f"\nTotal Leads Found (In-Scope): {total_found}")
