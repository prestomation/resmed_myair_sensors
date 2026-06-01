"""Region-specific ResMed myAir endpoint configuration."""

from dataclasses import dataclass

from custom_components.resmed_myair.const import REGION_EU, REGION_NA


@dataclass(frozen=True, slots=True)
class RegionConfig:
    """Static endpoints and client identifiers for one myAir region."""

    product: str
    okta_url: str
    email_factor_id: str
    auth_server_id: str
    authorize_client_id: str
    myair_api_key: str
    graphql_url: str
    oauth_redirect_url: str

    @property
    def authn_url(self) -> str:
        """Build the Okta primary-authentication endpoint URL."""
        return f"https://{self.okta_url}/api/v1/authn"

    @property
    def authorize_url(self) -> str:
        """Build the Okta authorization-code endpoint URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/authorize"

    @property
    def token_url(self) -> str:
        """Build the Okta token-exchange endpoint URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/token"

    @property
    def introspect_url(self) -> str:
        """Build the Okta access-token introspection endpoint URL."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/introspect"

    @property
    def userinfo_url(self) -> str:
        """Build the Okta userinfo endpoint URL used for account checks."""
        return f"https://{self.okta_url}/oauth2/{self.auth_server_id}/v1/userinfo"

    def mfa_url(self, email_factor_id: str | None = None) -> str:
        """Build the email-factor MFA endpoint for an auth challenge.

        Args:
            email_factor_id: Optional factor ID discovered from authn.

        Returns:
            Fully qualified Okta MFA verification URL.
        """
        factor_id = email_factor_id or self.email_factor_id
        return (
            f"https://{self.okta_url}/api/v1/authn/factors/{factor_id}/verify?rememberDevice=true"
        )


NA_CONFIG: RegionConfig = RegionConfig(
    # The name used in various queries
    product="myAir",
    # The regionalized URL for Okta authentication queries
    okta_url="resmed-ext-1.okta.com",
    # This is the ID that refers to the Email MFA Factor. Not currently setup/used in NA
    email_factor_id="xxx",
    # This is the server ID that is designated by Okta for myAir used in authentication urls
    auth_server_id="aus4ccsxvnidQgLmA297",
    # This is the ID that is designated by Okta for myAir that appears in request bodies
    # during login
    authorize_client_id="0oa4ccq1v413ypROi297",
    # Used as the x-api-key header for the AppSync GraphQL API
    myair_api_key="da2-cenztfjrezhwphdqtwtbpqvzui",
    # The AppSync URL that accepts the access token to return Sleep Records
    graphql_url="https://graphql.myair-prd.dht.live/graphql",
    # Redirect url for browser to go to once authentication is complete.
    # Must be the same as what is defined by Okta
    oauth_redirect_url="https://myair.resmed.com",
)

EU_CONFIG: RegionConfig = RegionConfig(
    # The name used in various queries
    product="myAir EU",
    # The regionalized URL for Okta authentication queries
    okta_url="id.resmed.eu",
    # This is the ID that refers to the Email MFA Factor
    email_factor_id="emfg9cmjqxEPr52cT417",
    # This is the server ID that is designated by Okta for myAir used in authentication urls
    auth_server_id="aus2uznux2sYKTsEg417",
    # This is the ID that is designated by Okta for myAir that appears in request
    # bodies during login
    authorize_client_id="0oa2uz04d2Pks2NgR417",
    # Used as the x-api-key header for the AppSync GraphQL API
    myair_api_key="da2-o66oo6xdnfh5hlfuw5yw5g2dtm",
    # The AppSync URL that accepts the access token to return Sleep Records
    graphql_url="https://graphql.hyperdrive.resmed.eu/graphql",
    # Redirect url for browser to go to once authentication is complete.
    # Must be the same as what is defined by Okta
    oauth_redirect_url="https://myair.resmed.eu",
)


def get_region_config(region: str) -> RegionConfig:
    """Resolve a user-selected region code to endpoint settings.

    Args:
        region: Region code configured by the user.

    Returns:
        Region-specific endpoint settings.

    Raises:
        ValueError: When the region code is not supported.
    """
    if region == REGION_NA:
        return NA_CONFIG
    if region == REGION_EU:
        return EU_CONFIG
    raise ValueError(f"Unsupported myAir region: {region}")
