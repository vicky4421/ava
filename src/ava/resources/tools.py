from tavily import TavilyClient

from config.logger import get_logger
from config.settings import settings

logger = get_logger()


def get_tavily_client() -> TavilyClient:
    '''Provides the shared Tavily client instance for interacting with the Tavily API.'''

    try:
        client = TavilyClient(settings.tavily_api_key)
        logger.info("Tavily Client initiated successfully.")
        return client
    except Exception as e:
        logger.critical(f"Unexpected error initializing tavily client: {e}")
        raise