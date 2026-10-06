import asyncio
import logging
import sys

from ava.agent.graph import app
from ava.banner import print_ava_banner
from ava.commands.logs import handle_logs
from ava.commands.scan import run_scan
from ava.config.logger import get_logger
from ava.config.paths import ROOT_DIR
from ava.parser import build_parser

logger = get_logger()

# silent gemini warnings
logging.getLogger(name="google_genai.models").setLevel(level=logging.ERROR)


async def async_main():

    png_data = app.get_graph().draw_mermaid_png()
    output_path = ROOT_DIR / "graphs" / "agent.png"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(png_data)

    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        print_ava_banner(target_apk=str(args.target))
        await run_scan(target=args.target)

    elif args.command == "logs":
        handle_logs(lines=args.lines, clear=args.clear, show_path=args.path)
    else:
        parser.print_help()
        sys.exit(0)

    print()


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.error("Analysis aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
