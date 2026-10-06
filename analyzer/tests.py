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
