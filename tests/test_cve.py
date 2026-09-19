import unittest

from bounty_surface.cve import fingerprint_response, match_kev


class CveTests(unittest.TestCase):
    def test_fingerprint_and_kev_match_are_evidence_based(self):
        tech = fingerprint_response(
            "https://example.com",
            {"server": "Apache/2.4.49", "x-powered-by": ""},
            "<html><body>hello</body></html>",
        )
        self.assertEqual(tech[0]["product"], "Apache HTTP Server")
        matches = match_kev(tech, [{
            "cveID": "CVE-2021-41773",
            "vendorProject": "Apache",
            "product": "HTTP Server",
            "dateAdded": "2021-11-03",
            "shortDescription": "test",
        }])
        self.assertEqual(matches[0]["cve"], "CVE-2021-41773")
        self.assertIn("candidate", matches[0]["confidence"])


if __name__ == "__main__":
    unittest.main()
