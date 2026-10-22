"""Client-credentials example; configure environment first. Author: Rajarshi."""
import asyncio
import os

import httpx

from general_ai_gateway.client_credentials import ClientCredentialsTokenProvider


async def main():
    async with ClientCredentialsTokenProvider(
        os.environ["OAUTH_TOKEN_ENDPOINT"],
        os.environ["OAUTH_CLIENT_ID"],
        os.environ["OAUTH_CLIENT_SECRET"],
        scope=os.getenv("OAUTH_SCOPE", "gateway:invoke"),
        audience=os.getenv("OAUTH_AUDIENCE"),
        resource=os.getenv("OAUTH_RESOURCE"),
    ) as tokens, httpx.AsyncClient(trust_env=False, timeout=30) as gateway:
        # Reuse the provider across requests; get_token() renews before expiry.
        access_token = await tokens.get_token()
        response = await gateway.get(
            os.environ["GATEWAY_URL"].rstrip("/") + "/v1/models",
            headers={"Authorization": "Bearer " + access_token},
        )
        response.raise_for_status()
        print(response.json())


if __name__ == "__main__":
    asyncio.run(main())
