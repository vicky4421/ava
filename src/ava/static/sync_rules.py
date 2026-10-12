# Author: Vivek Sawant
# Date: 12-10-2026

from dataclasses import dataclass
from enum import StrEnum


class VulnerabilityCategory(StrEnum):
    STORAGE = "Insecure Storage"
    WEBVIEW = "WebView Security"
    COMPONENT = "Component Hijacking / Redirection"
    CRYPTO = "Cryptographic Issue"
    CODE_EXEC = "Dynamic Code Loading"


@dataclass(frozen=True)
class SinkRule:
    rule_id: str
    category: VulnerabilityCategory
    description: str
    pattern: str  # Regex pattern matching Smali instructions
    is_intrinsic: bool  # True if the call itself is a flaw (e.g. MODE_WORLD_READABLE)
    confidence: str  # HIGH, MEDIUM, LOW


# Initial high-fidelity Android Smali rules
SMALI_RULES: list[SinkRule] = [
    # 1. Insecure SharedPreferences (MODE_WORLD_READABLE / 0x1)
    SinkRule(
        rule_id="SEC-STORE-001",
        category=VulnerabilityCategory.STORAGE,
        description="SharedPreferences opened with world-readable permissions.",
        pattern=r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/Context;->getSharedPreferences\(Ljava/lang/String;I\)Landroid/content/SharedPreferences;",
        is_intrinsic=True,
        confidence="HIGH",
    ),
    # 2. Insecure WebView JavaScript execution
    SinkRule(
        rule_id="SEC-WEB-001",
        category=VulnerabilityCategory.WEBVIEW,
        description="WebView JavaScript execution enabled.",
        pattern=r"invoke-virtual\s*\{[^}]+\},\s*Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V",
        is_intrinsic=True,
        confidence="MEDIUM",
    ),
    # 3. WebView JavaScript Interface (Bridge)
    SinkRule(
        rule_id="SEC-WEB-002",
        category=VulnerabilityCategory.WEBVIEW,
        description="Add JavascriptInterface exposed on WebView.",
        pattern=r"invoke-virtual\s*\{[^}]+\},\s*Landroid/webkit/WebView;->addJavascriptInterface\(Ljava/lang/Object;Ljava/lang/String;\)V",
        is_intrinsic=False,
        confidence="HIGH",
    ),
    # 4. Intent Redirection Sink (Starting component from incoming Intent)
    SinkRule(
        rule_id="SEC-COMP-001",
        category=VulnerabilityCategory.COMPONENT,
        description="Activity launch sink (potential intent redirection target).",
        pattern=r"invoke-virtual\s*\{[^}]+\},\s*Landroid/content/Context;->startActivity\(Landroid/content/Intent;\)V",
        is_intrinsic=False,
        confidence="MEDIUM",
    ),
    # 5. Dynamic Code Loading
    SinkRule(
        rule_id="SEC-EXEC-001",
        category=VulnerabilityCategory.CODE_EXEC,
        description="Dynamic DEX loading via DexClassLoader.",
        pattern=r"invoke-direct\s*\{[^}]+\},\s*Ldalvik/system/DexClassLoader;-><init>",
        is_intrinsic=True,
        confidence="HIGH",
    ),
]
