from pathlib import Path
from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from .models import TestProject, SecurityScan, TargetAsset, Service


class ImportSmokeTests(TestCase):
    def test_sample_import(self):
        data = Path('nmap_sample.xml').read_bytes()
        response = self.client.post('/api/upload-log/', {
            'project_name': 'Sample',
            'nmap_file': SimpleUploadedFile('sample.xml', data),
        })
        self.assertEqual(response.status_code, 200)
        self.assertEqual(TestProject.objects.count(), 1)
        self.assertEqual(SecurityScan.objects.count(), 1)
        self.assertEqual(TargetAsset.objects.count(), 1)
        self.assertEqual(Service.objects.count(), 2)
        self.assertEqual(self.client.get('/').status_code, 200)

    def test_invalid_xml_does_not_create_project(self):
        response = self.client.post('/api/upload-log/', {
            'nmap_file': SimpleUploadedFile('bad.xml', b'<nmaprun>'),
        })
        self.assertEqual(response.status_code, 400)
        self.assertFalse(TestProject.objects.exists())

    def test_sample_preserves_product_version_and_cpe(self):
        self.client.post('/api/upload-log/', {
            'nmap_file': SimpleUploadedFile('sample.xml', Path('nmap_sample.xml').read_bytes()),
        })
        scan = SecurityScan.objects.get()
        asset = scan.assets.get()
        self.assertEqual(asset.project, scan.project)
        self.assertEqual(scan.target, '127.0.0.1')
        self.assertEqual(scan.scan_method, 'nmap-import')
        ssh = asset.services.get(port=22)
        self.assertEqual(ssh.product, 'OpenSSH')
        self.assertEqual(ssh.service_version, '9.6p1 Ubuntu 3ubuntu13.16')
        self.assertIn('cpe:/a:openbsd:openssh:9.6p1', ssh.cpe)
        self.assertEqual(asset.services.get(port=631).product, 'CUPS')


class AnalysisStatusTests(TestCase):
    def setUp(self):
        from .views import import_nmap_file
        self.scan = import_nmap_file(SimpleUploadedFile('sample.xml', Path('nmap_sample.xml').read_bytes()))

    def response(self):
        import json
        from unittest.mock import Mock
        response = Mock()
        response.json.return_value = {'response': json.dumps({
            'title': 'Service review', 'category': 'service_configuration',
            'severity': 'low', 'evidence': 'Version observed', 'related_cve': [],
            'description': 'Review vendor support', 'recommendation': 'Apply vendor updates',
        })}
        return response

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post')
    def test_scan_outcomes(self, post, chroma):
        import requests
        from .analysis import analyze_scan
        from .models import SecurityFinding
        chroma.return_value.get_collection.side_effect = RuntimeError('Unavailable')
        for outcomes, expected, count in [
            ([self.response(), self.response()], SecurityScan.Status.COMPLETED, 2),
            ([self.response(), requests.ConnectionError()], SecurityScan.Status.PARTIAL, 1),
            ([requests.ConnectionError(), requests.ConnectionError()], SecurityScan.Status.FAILED, 0),
        ]:
            with self.subTest(status=expected):
                SecurityFinding.objects.all().delete()
                post.side_effect = outcomes
                result = analyze_scan(self.scan)
                self.scan.refresh_from_db()
                self.assertEqual(result['status'], expected)
                self.assertEqual(self.scan.status, expected)
                self.assertEqual(SecurityFinding.objects.count(), count)
