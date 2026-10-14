# Author: Vivek Sawant
# Date: 14-10-2026

# ~/ava/test_xref.py
from androguard.misc import AnalyzeAPK

apk_path = "/home/vivek/sample_apps/bugbazaar/BugBazaar_v1.2.1.apk"
a, d, dx = AnalyzeAPK(apk_path)

target_class = "Lcom/BugBazaar/ui/Deeplink;"
target_method = "setupwebview"

print(f"Tracing callers for {target_class}->{target_method}...")

for method in dx.find_methods(classname=target_class, methodname=target_method):
    for xref_class, xref_method, offset in method.get_xref_from():
        print(
            f"  Called by: {xref_class.get_class()} -> {xref_method.get_class_name()}"
        )
