import unittest

from hotpot.network import Allowlist


class AllowlistTests(unittest.TestCase):
    def test_ipv4_and_ipv6_cidrs(self):
        allow = Allowlist(("192.168.1.0/24", "2001:db8::/32", "10.0.0.5"))
        self.assertTrue(allow.contains("192.168.1.44"))
        self.assertTrue(allow.contains("10.0.0.5"))
        self.assertTrue(allow.contains("2001:db8::1234"))
        self.assertFalse(allow.contains("192.168.2.44"))
        self.assertFalse(allow.contains("not-an-ip"))

    def test_invalid_cidr_fails_fast(self):
        with self.assertRaises(RuntimeError):
            Allowlist(("192.168.1.999/24",))


if __name__ == "__main__":
    unittest.main()
