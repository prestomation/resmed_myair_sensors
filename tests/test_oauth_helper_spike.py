"""Tests documenting OAuth helper feasibility for ResMed myAir."""

from custom_components.resmed_myair.client.rest_client import EU_CONFIG, NA_CONFIG


def test_resmed_registered_redirect_urls_are_external() -> None:
    """ResMed's app redirect URLs are not Home Assistant callback URLs."""
    redirect_urls = {
        NA_CONFIG.oauth_redirect_url,
        EU_CONFIG.oauth_redirect_url,
    }

    assert redirect_urls == {
        "https://myair.resmed.com",
        "https://myair.resmed.eu",
    }
    assert all("/auth/external/callback" not in url for url in redirect_urls)
