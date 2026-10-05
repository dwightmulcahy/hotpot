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


class ClientIPResolverTests(unittest.TestCase):
    def test_cloudflare_header_from_trusted_proxy(self):
        from hotpot.network import ClientIPResolver

        resolver = ClientIPResolver("cloudflare", ("172.30.0.0/24",))
        identity = resolver.resolve(
            "172.30.0.10", {"CF-Connecting-IP": "203.0.113.42"}
        )
        self.assertEqual(identity.client_ip, "203.0.113.42")
        self.assertEqual(identity.proxy_ip, "172.30.0.10")
        self.assertEqual(identity.source, "cf-connecting-ip")
        self.assertTrue(identity.trusted_proxy)

    def test_cloudflare_header_from_untrusted_peer_is_ignored(self):
        from hotpot.network import ClientIPResolver

        resolver = ClientIPResolver("cloudflare", ("172.30.0.0/24",))
        identity = resolver.resolve(
            "198.51.100.77", {"CF-Connecting-IP": "203.0.113.42"}
        )
        self.assertEqual(identity.client_ip, "198.51.100.77")
        self.assertEqual(identity.source, "peer")
        self.assertFalse(identity.trusted_proxy)

    def test_cloudflare_mode_requires_trusted_proxies(self):
        from hotpot.network import ClientIPResolver

        with self.assertRaises(RuntimeError):
            ClientIPResolver("cloudflare", ())

    def test_invalid_cloudflare_ip_falls_back_to_peer(self):
        from hotpot.network import ClientIPResolver

        resolver = ClientIPResolver("cloudflare", ("172.30.0.0/24",))
        identity = resolver.resolve(
            "172.30.0.10", {"CF-Connecting-IP": "definitely-not-an-ip"}
        )
        self.assertEqual(identity.client_ip, "172.30.0.10")
        self.assertEqual(identity.source, "peer-invalid-cf-connecting-ip")

    def test_x_forwarded_for_mode_uses_leftmost_ip(self):
        from hotpot.network import ClientIPResolver

        resolver = ClientIPResolver("x-forwarded-for", ("10.0.0.0/8",))
        identity = resolver.resolve(
            "10.1.2.3", {"X-Forwarded-For": "203.0.113.9, 10.2.3.4"}
        )
        self.assertEqual(identity.client_ip, "203.0.113.9")
        self.assertEqual(identity.source, "x-forwarded-for")


if __name__ == "__main__":
    unittest.main()
