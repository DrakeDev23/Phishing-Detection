import os
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

os.environ.setdefault("GEMINI_API_KEY", "test-key")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import url_checker


class FakeResponse:
    def __init__(self, status_code, location=None):
        self.status_code = status_code
        self.headers = {} if location is None else {"location": location}


class FakeStream:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error

    async def __aenter__(self):
        if self.error:
            raise self.error
        return self.response

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class FakeClient:
    def __init__(self, streams):
        self.streams = iter(streams)
        self.requests = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def stream(self, method, url, headers):
        self.requests.append((method, url, headers))
        return next(self.streams)


class RedirectValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_to_blocked_target_is_never_requested(self):
        client = FakeClient([FakeStream(FakeResponse(302, "http://127.0.0.1/admin"))])
        with (
            patch.object(url_checker.httpx, "AsyncClient", return_value=client),
            patch.object(
                url_checker,
                "validate_url_target",
                new=AsyncMock(side_effect=[(True, ""), (False, "Blocked private")]),
            ),
        ):
            result = await url_checker.check_single_link("https://public.example", {})

        self.assertEqual(len(client.requests), 1)
        self.assertEqual(result.error, "Redirect blocked: Blocked private")
        self.assertIsNone(result.status_code)

    async def test_follows_validated_relative_redirect(self):
        client = FakeClient([
            FakeStream(FakeResponse(302, "/login")),
            FakeStream(FakeResponse(200)),
        ])
        with (
            patch.object(url_checker.httpx, "AsyncClient", return_value=client),
            patch.object(url_checker, "validate_url_target", new=AsyncMock(return_value=(True, ""))),
        ):
            result = await url_checker.check_single_link("https://public.example", {})

        self.assertEqual([request[1] for request in client.requests], [
            "https://public.example", "https://public.example/login",
        ])
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.redirect_url, "https://public.example/login")

    async def test_stops_after_configured_redirect_limit(self):
        client = FakeClient([
            FakeStream(FakeResponse(302, f"/step-{index}"))
            for index in range(url_checker.MAX_REDIRECTS + 1)
        ])
        with (
            patch.object(url_checker.httpx, "AsyncClient", return_value=client),
            patch.object(url_checker, "validate_url_target", new=AsyncMock(return_value=(True, ""))),
        ):
            result = await url_checker.check_single_link("https://public.example", {})

        self.assertEqual(len(client.requests), url_checker.MAX_REDIRECTS + 1)
        self.assertEqual(result.error, f"Too many redirects (maximum {url_checker.MAX_REDIRECTS})")
        self.assertIsNone(result.status_code)

    async def test_timeout_returns_existing_error_shape(self):
        client = FakeClient([FakeStream(error=httpx.TimeoutException("timed out"))])
        with (
            patch.object(url_checker.httpx, "AsyncClient", return_value=client),
            patch.object(url_checker, "validate_url_target", new=AsyncMock(return_value=(True, ""))),
        ):
            result = await url_checker.check_single_link("https://public.example", {})

        self.assertEqual(result.error, "Request timed out")
        self.assertFalse(result.is_alive)
