import asyncio
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

os.environ.setdefault("GEMINI_API_KEY", "test-key")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import security


class BlockedAddressTests(unittest.TestCase):
    def test_blocks_non_public_address_categories(self):
        addresses = [
            "127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
            "169.254.169.254", "100.64.0.1", "224.0.0.1", "240.0.0.1",
            "0.0.0.0", "::1", "fc00::1", "fe80::1", "ff02::1", "::",
        ]
        for address in addresses:
            with self.subTest(address=address):
                self.assertTrue(security.is_blocked_ip(address))

    def test_allows_public_addresses(self):
        self.assertFalse(security.is_blocked_ip("8.8.8.8"))
        self.assertFalse(security.is_blocked_ip("2606:4700:4700::1111"))


class UrlTargetValidationTests(unittest.IsolatedAsyncioTestCase):
    async def test_blocks_literal_loopback_without_dns_lookup(self):
        with patch.object(security, "resolve_host_addresses", new_callable=AsyncMock) as resolver:
            safe, reason = await security.validate_url_target("http://127.0.0.1/admin")
        self.assertFalse(safe)
        self.assertIn("internal/private", reason)
        resolver.assert_not_awaited()

    async def test_blocks_hostname_resolving_to_private_address(self):
        with patch.object(
            security, "resolve_host_addresses", new=AsyncMock(return_value={"169.254.169.254"})
        ):
            safe, reason = await security.validate_url_target("https://attacker.example/path")
        self.assertFalse(safe)
        self.assertIn("resolves", reason)

    async def test_blocks_mixed_public_and_private_dns_answers(self):
        with patch.object(
            security,
            "resolve_host_addresses",
            new=AsyncMock(return_value={"8.8.8.8", "10.0.0.10"}),
        ):
            safe, _ = await security.validate_url_target("https://attacker.example")
        self.assertFalse(safe)

    async def test_allows_hostname_with_only_public_dns_answers(self):
        with patch.object(
            security, "resolve_host_addresses", new=AsyncMock(return_value={"8.8.8.8"})
        ):
            safe, reason = await security.validate_url_target("https://public.example:8443/path")
        self.assertTrue(safe)
        self.assertEqual(reason, "")

    async def test_fails_closed_when_dns_lookup_fails(self):
        with patch.object(
            security,
            "resolve_host_addresses",
            new=AsyncMock(side_effect=socket.gaierror),
        ):
            safe, reason = await security.validate_url_target("https://unresolvable.example")
        self.assertFalse(safe)
        self.assertIn("resolved safely", reason)

