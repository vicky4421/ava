import asyncio

from ava.banner import print_ava_banner


async def async_main():
    print_ava_banner()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
