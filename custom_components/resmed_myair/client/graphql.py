"""GraphQL transport for ResMed myAir."""

import logging
from typing import Any

from aiohttp import ClientSession
import jwt
from jwt import InvalidTokenError

from custom_components.resmed_myair.redaction import redact_dict

from .auth import MyAirAuthSession
from .myair_client import ParsingError
from .regions import RegionConfig

_LOGGER: logging.Logger = logging.getLogger(__name__)


class MyAirGraphQLClient:
    """Execute authenticated ResMed AppSync operations for myAir data."""

    def __init__(
        self, session: ClientSession, auth: MyAirAuthSession, region_config: RegionConfig
    ) -> None:
        """Bind GraphQL requests to the shared session and auth state.

        Args:
            session: Shared aiohttp client session.
            auth: Auth session that owns tokens.
            region_config: Region endpoint configuration.
        """
        self._session = session
        self._auth = auth
        self._region_config = region_config
        self._country_code: str | None = None

    @property
    def country_code(self) -> str | None:
        """Expose the cached myAir country code used for AppSync headers."""
        return self._country_code

    @country_code.setter
    def country_code(self, value: str | None) -> None:
        """Cache the myAir country code used for AppSync headers.

        Args:
            value: myAir country code, or ``None`` to force token decoding later.
        """
        self._country_code = value

    async def query(self, operation_name: str, query: str, initial: bool = False) -> dict[str, Any]:
        """Post a myAir GraphQL operation and validate ResMed errors.

        Args:
            operation_name: GraphQL operation name.
            query: GraphQL query text.
            initial: Whether this query is part of initial config flow.

        Returns:
            Decoded GraphQL response payload.
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
            await MyAirAuthSession.resmed_response_error_check(
                "gql_query", records_res, records_dict, initial
            )

        return dict(records_dict)

    def _headers(self) -> dict[str, str]:
        """Build AppSync headers from regional constants and token claims.

        Returns:
            Headers accepted by ResMed's myAir GraphQL endpoint.

        Raises:
            ParsingError: When no country code can be derived for AppSync.
        """
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
        """Decode the unsigned ID token claim used by ResMed's country header.

        Returns:
            myAir country code, or ``None`` when no ID token is available yet.

        Raises:
            ParsingError: When the ID token cannot be decoded or lacks the claim.
        """
        if not self._auth.id_token:
            return None
        try:
            jwt_data: dict[str, Any] = jwt.decode(
                self._auth.id_token, options={"verify_signature": False}
            )
        except (InvalidTokenError, ValueError) as err:
            raise ParsingError("Unable to decode id_token into jwt_data") from err
        country_code = jwt_data.get("myAirCountryId")
        if not isinstance(country_code, str):
            raise ParsingError("myAirCountryId not found in jwt_data")
        return country_code
