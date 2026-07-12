import os
import sys
import unittest
from pathlib import Path

os.environ.setdefault("GEMINI_API_KEY", "test-key")
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishing_detector import compute_risk_level, heuristic_phishing_check


class HeuristicScoringTests(unittest.TestCase):
    def test_tld_alone_is_not_suspicious(self):
        suspicious, flags, score = heuristic_phishing_check("https://portfolio.xyz")

        self.assertTrue(suspicious)
        self.assertEqual(score, 1)
        self.assertEqual(compute_risk_level(score, None, flags), "safe")

    def test_high_risk_tld_with_credential_lure_is_suspicious(self):
        suspicious, flags, score = heuristic_phishing_check("https://account-verify.xyz/login")

        self.assertTrue(suspicious)
        self.assertGreaterEqual(score, 4)
        self.assertEqual(compute_risk_level(score, None, flags), "suspicious")

    def test_long_url_alone_does_not_create_a_phishing_verdict(self):
        url = "https://example.com/path?token=" + "a" * 220
        _, flags, score = heuristic_phishing_check(url)

        self.assertEqual(score, 1)
        self.assertEqual(compute_risk_level(score, None, flags), "safe")

    def test_trusted_domain_no_longer_bypasses_high_confidence_form_signal(self):
        suspicious, flags, score = heuristic_phishing_check(
            "https://attacker.wordpress.com/registration_form.php"
        )

        self.assertTrue(suspicious)
        self.assertIn("Credential harvesting form path detected", flags)
        self.assertEqual(compute_risk_level(score, None, flags), "dangerous")

    def test_userinfo_host_disguise_is_high_risk(self):
        suspicious, flags, score = heuristic_phishing_check("https://paypal.com@safe.example/login")

        self.assertTrue(suspicious)
        self.assertIn("URL contains embedded credentials/userinfo — common host-disguise technique", flags)
        self.assertEqual(compute_risk_level(score, None, flags), "suspicious")

    def test_punycode_is_a_contextual_signal(self):
        suspicious, flags, score = heuristic_phishing_check("https://xn--paypa-9za.example")

        self.assertTrue(suspicious)
        self.assertIn("Punycode domain detected — review for a possible homograph attack", flags)
        self.assertEqual(compute_risk_level(score, None, flags), "safe")

    def test_virustotal_malicious_result_is_dangerous(self):
        self.assertEqual(
            compute_risk_level(0, None, [], virustotal_malicious=True),
            "dangerous",
        )
