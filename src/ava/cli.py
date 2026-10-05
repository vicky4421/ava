import asyncio
import sys

from ava.banner import print_ava_banner
from ava.commands.logs import handle_logs
from ava.commands.scan import run_scan
from ava.config.logger import get_logger
from ava.parser import build_parser

logger = get_logger()


async def async_main():
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


def main():
    try:
        asyncio.run(async_main())
    except KeyboardInterrupt:
        logger.error("Analysis aborted by user.")
        sys.exit(130)


if __name__ == "__main__":
    main()
