from unittest.mock import patch

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase

from .models import ExploitSuggestion, SecurityProject, TargetAsset


class NmapUploadTests(TestCase):
    host = ('<host><status state="up"/><address addr="192.0.2.1" '
            'addrtype="ipv4"/><ports><port portid="22"><state state="open"/>'
            '<service name="ssh"/></port></ports></host>')

    def upload(self, xml):
        return self.client.post('/api/upload-log/', {
            'project_name': 'Test scan',
            'nmap_file': SimpleUploadedFile('scan.xml', xml.encode(),
                                           content_type='application/xml'),
        })

    def test_invalid_uploads_create_no_records(self):
        invalid_host = self.host.replace('portid="22"', 'portid="invalid"')
        for xml, message in [
            ('', 'XML không hợp lệ'),
            ('<nmaprun><host>', 'XML không hợp lệ'),
            ('<document/>', 'không phải kết quả quét Nmap'),
            ('<nmaprun/>', 'không chứa máy mục tiêu'),
            ('<nmaprun><host><status state="down"/></host></nmaprun>',
             'không chứa máy mục tiêu'),
            ('<nmaprun>' + self.host + invalid_host + '</nmaprun>',
             'Số cổng'),
            ('<nmaprun>' + self.host.replace('192.0.2.1', 'invalid') + '</nmaprun>',
             'Địa chỉ IP'),
            ('<nmaprun><host/></nmaprun>', 'thiếu địa chỉ IP'),
            ('<nmaprun>' + self.host.replace('portid="22"', 'portid="65536"')
             + '</nmaprun>', 'Số cổng'),
        ]:
            with self.subTest(xml=xml):
                response = self.upload(xml)
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['status'], 'error')
                self.assertIn(message, response.json()['message'])
                self.assertEqual(SecurityProject.objects.count(), 0)
                self.assertEqual(TargetAsset.objects.count(), 0)
                self.assertEqual(ExploitSuggestion.objects.count(), 0)

    def test_valid_upload_creates_project_asset_and_service(self):
        response = self.upload('<nmaprun>' + self.host + '</nmaprun>')
        self.assertEqual(response.status_code, 200)
        project = SecurityProject.objects.get(pk=response.json()['project_id'])
        asset = project.assets.get()
        self.assertEqual(asset.ip_address, '192.0.2.1')
        self.assertEqual(asset.vulnerabilities.get().port, 22)

    def test_save_failure_rolls_back_project_and_asset(self):
        with patch('analyzer.views.ExploitSuggestion.objects.create',
                   side_effect=RuntimeError('save failed')):
            with self.assertRaisesMessage(RuntimeError, 'save failed'):
                self.upload('<nmaprun>' + self.host + '</nmaprun>')
        self.assertEqual(SecurityProject.objects.count(), 0)
        self.assertEqual(TargetAsset.objects.count(), 0)
        self.assertEqual(ExploitSuggestion.objects.count(), 0)

    def test_missing_file_returns_error(self):
        response = self.client.post('/api/upload-log/', {'project_name': 'Test'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(SecurityProject.objects.count(), 0)
