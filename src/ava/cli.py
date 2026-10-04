import asyncio

from ava.banner import print_ava_banner
from ava.resources.models import load_hf_embedding_model


async def async_main():
    print_ava_banner()
    load_hf_embedding_model()


def main():
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
