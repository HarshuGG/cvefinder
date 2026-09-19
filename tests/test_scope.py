import unittest

from bounty_surface.scope import Scope


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = Scope(
            "demo",
            ["example.com", "*.example.com"],
            ["admin.example.com", "*.internal.example.com"],
            ["https"],
        )

    def test_root_and_subdomain_are_allowed(self):
        self.assertTrue(self.scope.allows_url("https://example.com"))
        self.assertTrue(self.scope.allows_url("https://app.example.com/path"))

    def test_exclusions_and_scheme_are_denied(self):
        self.assertFalse(self.scope.allows_url("https://admin.example.com"))
        self.assertFalse(self.scope.allows_url("https://x.internal.example.com"))
        self.assertFalse(self.scope.allows_url("http://example.com"))
        self.assertFalse(self.scope.allows_url("https://example.net"))


if __name__ == "__main__":
    unittest.main()
