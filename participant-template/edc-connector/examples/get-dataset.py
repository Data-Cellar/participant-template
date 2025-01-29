import asyncio
import logging
import os
import pprint

import coloredlogs
import httpx
from edcpy.edc_api import ConnectorController
from edcpy.messaging import HttpPullMessage, with_messaging_app

_ENV_LOG_LEVEL = "LOG_LEVEL"
_ENV_COUNTER_PARTY_PROTOCOL_URL = "COUNTER_PARTY_PROTOCOL_URL"
_ENV_COUNTER_PARTY_CONNECTOR_ID = "COUNTER_PARTY_CONNECTOR_ID"
_ENV_ASSET_QUERY = "ASSET_QUERY"

_logger = logging.getLogger(__name__)


async def pull_handler(message: dict, queue: asyncio.Queue):
    """Put an HTTP Pull message received from the Rabbit broker into a queue."""

    # Using type hints for the message argument seems to break in Python 3.8.
    message = HttpPullMessage(**message)

    _logger.info(
        "Putting HTTP Pull request into the queue:\n%s", pprint.pformat(message.dict())
    )

    # Using a queue is not strictly necessary.
    # We just need an asyncio-compatible way to pass
    # the messages from the broker to the main function.
    await queue.put(message)


async def main():
    """List the assets available in the Provider's catalogue."""

    counter_party_protocol_url: str = os.getenv(_ENV_COUNTER_PARTY_PROTOCOL_URL)
    counter_party_connector_id: str = os.getenv(_ENV_COUNTER_PARTY_CONNECTOR_ID)
    asset_query: str = os.getenv(_ENV_ASSET_QUERY)

    if not all([counter_party_protocol_url, counter_party_connector_id, asset_query]):
        raise ValueError(
            f"Environment variables {_ENV_COUNTER_PARTY_PROTOCOL_URL}, {_ENV_COUNTER_PARTY_CONNECTOR_ID}, and {_ENV_ASSET_QUERY} must be set"
        )

    controller = ConnectorController()

    _logger.debug("Configuration:\n%s", controller.config)

    queue: asyncio.Queue[HttpPullMessage] = asyncio.Queue()

    async def pull_handler_partial(message: dict):
        await pull_handler(message=message, queue=queue)

    async with with_messaging_app(http_pull_handler=pull_handler_partial):
        transfer_details = await controller.run_negotiation_flow(
            counter_party_protocol_url=counter_party_protocol_url,
            counter_party_connector_id=counter_party_connector_id,
            asset_query=asset_query,
        )

        transfer_process_id = await controller.run_transfer_flow(
            transfer_details=transfer_details, is_provider_push=False
        )

        _logger.info("Transfer process ID: %s", transfer_process_id)

        http_pull_msg = await asyncio.wait_for(queue.get(), timeout=20)

        async with httpx.AsyncClient() as client:
            request_args = {**http_pull_msg.request_args}

            # ToDo: This is a workaround to fix an issue with the reverse proxy
            request_args["url"] = "{}/".format(request_args["url"].rstrip("/"))

            _logger.info(
                "Sending HTTP GET request with arguments:\n%s",
                pprint.pformat(request_args),
            )

            resp = await client.request(**request_args)
            _logger.info("Response dataset:\n%s", pprint.pformat(resp.json()))


if __name__ == "__main__":
    coloredlogs.install(level=os.getenv(_ENV_LOG_LEVEL, "DEBUG"))
    asyncio.run(main())
