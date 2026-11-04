"""Test cho các phần đào sâu: khớp CVE theo khoảng phiên bản và chống bịa CVE."""
from django.test import SimpleTestCase

from .analysis import version_in_range, matching_cves, grounded_cves, validate_review
from .fetch_nvd_cve import parse_cve_item


def _review(**changes):
    base = {'title': 'Xem xét dịch vụ', 'category': 'service_configuration',
            'severity': 'medium', 'evidence': 'Phiên bản lấy từ dữ liệu quét',
            'related_cve': [], 'description': 'Rà soát hỗ trợ nhà cung cấp',
            'recommendation': 'Cập nhật bản vá được hỗ trợ'}
    base.update(changes)
    return base


class FakeService:
    def __init__(self, product="openssh", version="9.6p1", cpe=""):
        self.product = product
        self.service_version = version
        self.cpe = cpe


class VersionRangeTests(SimpleTestCase):
    def test_version_in_range_operators(self):
        self.assertTrue(version_in_range("9.6p1", "8.5", "ge", "9.8", "lt"))
        self.assertTrue(version_in_range("8.5", "8.5", "ge", "9.8", "lt"))      # biên dưới inclusive
        self.assertFalse(version_in_range("8.5", "8.5", "gt", "9.8", "lt"))     # biên dưới exclusive
        self.assertFalse(version_in_range("9.8", "8.5", "ge", "9.8", "lt"))     # biên trên exclusive
        self.assertTrue(version_in_range("9.8", "8.5", "ge", "9.8", "le"))      # biên trên inclusive
        self.assertFalse(version_in_range("10.0", "8.5", "ge", "9.8", "lt"))    # ngoài khoảng
        self.assertFalse(version_in_range("abc", "8.5", "ge", "9.8", "lt"))     # không parse được
        self.assertFalse(version_in_range("9.0", "", None, "", None))           # không có khoảng

    def test_matching_cves_uses_range(self):
        meta = {"cve_id": "CVE-2024-6387", "product": "openssh",
                "version_start": "8.5", "version_start_op": "ge",
                "version_end": "9.8", "version_end_op": "lt"}
        records = [("CVE-2024-6387 OpenSSH advisory", meta, "collection_cve")]
        # 9.6p1 nằm trong [8.5, 9.8) -> khớp
        self.assertEqual(matching_cves(FakeService(version="9.6p1"), records), {"CVE-2024-6387"})
        # 10.0 ngoài khoảng -> không khớp
        self.assertEqual(matching_cves(FakeService(version="10.0"), records), set())
        # khác sản phẩm -> không khớp dù cùng khoảng
        self.assertEqual(matching_cves(FakeService(product="nginx", version="9.6"), records), set())


class GroundedCveTests(SimpleTestCase):
    def test_grounded_only_from_rag(self):
        records = [("Liên quan CVE-2024-1111 trong tài liệu",
                    {"cve_id": "CVE-2024-2222"}, "collection_cve")]
        grounded = grounded_cves(records)
        self.assertEqual(grounded, {"CVE-2024-1111", "CVE-2024-2222"})
        self.assertNotIn("CVE-2099-9999", grounded)  # CVE model bịa ra sẽ bị loại


class ValidateReviewTests(SimpleTestCase):
    def test_valid_review_passes(self):
        out = validate_review(_review())
        self.assertEqual(out['related_cve'], [])
        self.assertEqual(out['severity'], 'medium')

    def test_missing_evidence_rejected(self):
        with self.assertRaises(ValueError):
            validate_review(_review(evidence=''))

    def test_cve_in_prose_must_be_declared(self):
        # CVE nêu trong mô tả nhưng không khai báo -> loại
        with self.assertRaises(ValueError):
            validate_review(_review(description='Liên quan CVE-2024-5555'))
        # cùng CVE đó nhưng đã khai báo -> hợp lệ
        out = validate_review(_review(description='Liên quan CVE-2024-5555',
                                      related_cve=['CVE-2024-5555']))
        self.assertIn('CVE-2024-5555', out['related_cve'])

    def test_too_many_cves_rejected(self):
        many = [f'CVE-2024-{i:04d}' for i in range(1, 12)]  # 11 CVE
        with self.assertRaises(ValueError):
            validate_review(_review(related_cve=many))


class ActiveScanTests(SimpleTestCase):
    def _scanner(self, fetch):
        from .active_scan import ActiveScanner
        s = ActiveScanner()
        s._fetch = fetch
        return s

    def test_lab_host_guard_blocks_public(self):
        from .active_scan import ActiveScanner, is_lab_host
        self.assertTrue(is_lab_host("127.0.0.1"))
        self.assertTrue(is_lab_host("192.168.1.10"))
        self.assertTrue(is_lab_host("localhost"))
        self.assertFalse(is_lab_host("8.8.8.8"))
        self.assertFalse(is_lab_host("example.com"))
        rep = ActiveScanner().scan("http://8.8.8.8/x?q=1")  # công khai -> từ chối, KHÔNG gửi request
        self.assertEqual([f["cve"] for f in rep["findings"]], ["BLOCKED-SCOPE"])

    def test_no_param(self):
        from .active_scan import ActiveScanner
        rep = ActiveScanner().scan("http://127.0.0.1:3000/")
        self.assertEqual(rep["findings"][0]["cve"], "INFO-NO-PARAM")

    def test_detects_sqli_and_xss_html(self):
        from urllib.parse import urlparse, parse_qs
        def fetch(url):
            val = parse_qs(urlparse(url).query).get("q", [""])[0]
            if "<x>" in val:
                return (f"<html><body>echo {val}</body></html>", "text/html")
            if val.endswith("'"):
                return ("you have an error in your SQL syntax near ''", "text/html")
            return ("<html>normal</html>", "text/html")
        rep = self._scanner(fetch).scan("http://127.0.0.1:3000/search?q=test")
        cves = [f["cve"] for f in rep["findings"]]
        self.assertIn("ACTIVE-XSS-REFLECTED", cves)
        self.assertIn("ACTIVE-SQLI-ERROR", cves)

    def test_json_reflection_not_high_xss(self):
        from urllib.parse import urlparse, parse_qs
        def fetch(url):
            val = parse_qs(urlparse(url).query).get("q", [""])[0]
            if "<x>" in val:
                return ('{"q":"' + val + '"}', "application/json")
            return ('{"ok":1}', "application/json")
        rep = self._scanner(fetch).scan("http://127.0.0.1:3000/rest/products/search?q=test")
        cves = [f["cve"] for f in rep["findings"]]
        self.assertIn("ACTIVE-XSS-REFLECT-INPUT", cves)   # hạ mức vì không phải HTML
        self.assertNotIn("ACTIVE-XSS-REFLECTED", cves)


class NvdParseRangeTests(SimpleTestCase):
    def test_parse_extracts_version_range(self):
        item = {"cve": {"id": "CVE-2024-6387",
                        "descriptions": [{"lang": "en", "value": "race condition"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}]},
                        "configurations": [{"nodes": [{"cpeMatch": [{
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                            "versionStartIncluding": "8.5",
                            "versionEndExcluding": "9.8"}]}]}]}}
        rec = parse_cve_item(item)
        self.assertEqual(rec["version_start"], "8.5")
        self.assertEqual(rec["version_start_op"], "ge")
        self.assertEqual(rec["version_end"], "9.8")
        self.assertEqual(rec["version_end_op"], "lt")
        self.assertEqual(rec["product"], "openssh")
