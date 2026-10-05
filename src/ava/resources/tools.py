import subprocess
from pathlib import Path

from tavily import TavilyClient

from ava.config.logger import get_logger
from ava.config.settings import settings

logger = get_logger()


def get_tavily_client() -> TavilyClient:
    """Provides the shared Tavily client instance for interacting with the Tavily API."""

    try:
        client = TavilyClient(settings.tavily_api_key)
        logger.info("Tavily Client initiated successfully.")
        return client
    except Exception as e:
        logger.critical(f"Unexpected error initializing tavily client: {e}")
        raise


def decompile_apk(apk_path: str, output_dir: str | None = None) -> str:
    """Decompiles an Android APK using apktool to extract AndroidManifest.xml, resources, and Smali code."""

    logger.info(f"Decompiling {apk_path}...")

    apk = Path(apk_path).resolve()
    if not apk.exists() or apk.suffix.lower() != ".apk":
        return (
            f"Error: Target file {apk_path} does not exist or is not a valid .apk file."
        )

    target_dir = (
        Path(output_dir) if output_dir else apk.parent / f"{apk.stem}_decompiled"
    )

    cmd = ["apktool", "d", str(apk), "-o", str(target_dir), "-f"]
    try:
        result = subprocess.run(
            args=cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        logger.info(
            f"Successfully decompiled {apk.name} to {target_dir}.\n"
            f"Manifest location: {target_dir / 'AndroidManifest.xml'}\n"
        )
        return (
            f"Successfully decompiled {apk.name} to {target_dir}.\n"
            f"Manifest location: {target_dir / 'AndroidManifest.xml'}\n"
            f"Output Summary:\n{result.stdout[-300:]}"
        )
    except subprocess.CalledProcessError as e:
        return f"Apktool failed with return code {e.returncode}.\nError details:\n{e.stderr}"
    except FileNotFoundError:
        return "Error: apktool binary is not installed or not found in system PATH."
