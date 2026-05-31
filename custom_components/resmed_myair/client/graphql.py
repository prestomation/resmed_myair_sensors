"""GraphQL transport for ResMed myAir."""

import logging
from typing import Any

from aiohttp import ClientSession
import jwt

from .auth import MyAirAuthSession
from .helpers import redact_dict
from .myair_client import ParsingError
from .regions import RegionConfig

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MyAirGraphQLClient:
    """Execute ResMed AppSync GraphQL operations."""

    def __init__(
        self, session: ClientSession, auth: MyAirAuthSession, region_config: RegionConfig
    ) -> None:
        """Initialize the GraphQL client.

        Args:
            session: Shared aiohttp client session.
            auth: Auth session that owns tokens.
            region_config: Region endpoint configuration.
        """
        self._session = session
        self._auth = auth
        self._region_config = region_config
        self._country_code: str | None = None

    async def query(self, operation_name: str, query: str, initial: bool = False) -> dict[str, Any]:
        """Run a GraphQL query.

        Args:
            operation_name: GraphQL operation name.
            query: GraphQL query text.
            initial: Whether this query is part of initial config flow.

        Returns:
            Decoded JSON response.
        """
        headers = self._headers()
        json_query: dict[str, Any] = {
            "operationName": operation_name,
            "variables": {},
            "query": query,
        }
        _LOGGER.debug("[gql_query] graphql_url: %s", self._region_config.graphql_url)
        _LOGGER.debug("[gql_query] headers: %s", redact_dict(headers))
        _LOGGER.debug("[gql_query] json_query: %s", redact_dict(json_query))

        async with self._session.post(
            self._region_config.graphql_url,
            headers=headers,
            json=json_query,
        ) as records_res:
            _LOGGER.debug("[gql_query] records_res: %s", records_res)
            records_dict: dict[str, Any] = await records_res.json()
            _LOGGER.debug("[gql_query] records_dict: %s", redact_dict(records_dict))
            await MyAirAuthSession._resmed_response_error_check(  # noqa: SLF001
                "gql_query", records_res, records_dict, initial
            )

        return dict(records_dict)

    def _headers(self) -> dict[str, str]:
        """Return headers required by ResMed AppSync."""
        country_code: str | None = self._country_code or self._country_code_from_id_token()
        if not country_code:
            raise ParsingError("country_code not defined and id_token not present to identify it")
        self._country_code = country_code
        return {
            "x-api-key": self._region_config.myair_api_key,
            "Authorization": f"Bearer {self._auth.access_token}",
            "rmdhandsetid": "02c1c662-c289-41fd-a9ae-196ff15b5166",
            "rmdlanguage": "en",
            "rmdhandsetmodel": "Chrome",
            "rmdhandsetosversion": "127.0.6533.119",
            "rmdproduct": self._region_config.product,
            "rmdappversion": "1.0.0",
            "rmdhandsetplatform": "Web",
            "rmdcountry": country_code,
            "accept-language": "en-US,en;q=0.9",
        }

    def _country_code_from_id_token(self) -> str | None:
        """Derive the myAir country code from the ID token."""
        if not self._auth.id_token:
            return None
        try:
            jwt_data: dict[str, Any] = jwt.decode(
                self._auth.id_token, options={"verify_signature": False}
            )
        except jwt.PyJWTError as err:
            raise ParsingError("Unable to decode id_token into jwt_data") from err
        country_code = jwt_data.get("myAirCountryId")
        if not isinstance(country_code, str):
            raise ParsingError("myAirCountryId not found in jwt_data")
        return country_code
