from pathlib import Path

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
