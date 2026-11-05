import json
from io import BytesIO
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from django.contrib import admin
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, SimpleTestCase, TestCase, override_settings

from .analysis import analyze_scan, matching_cves
from .models import (TestProject, FunctionalTestCase, FunctionalTestRun, TestStepResult,
                     SecurityScan, TargetAsset, Service, SecurityFinding)
from .parse_nmap import parse_nmap_xml
from .views import import_nmap_file

SAMPLE = Path(__file__).resolve().parent.parent / 'nmap_sample.xml'
HOST = ('<host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>'
        '<ports><port protocol="tcp" portid="22"><state state="open"/>'
        '<service name="ssh" product="OpenSSH" version="9.6p1">'
        '<cpe>cpe:/a:openbsd:openssh:9.6p1</cpe></service></port></ports></host>')


def upload_file(data=None):
    return SimpleUploadedFile('scan.xml', SAMPLE.read_bytes() if data is None else data,
                              content_type='application/xml')


def ai_response(**changes):
    review = {'title': 'Review service support', 'category': 'outdated_service',
              'severity': 'medium', 'evidence': 'Service version from scan',
              'related_cve': [], 'description': 'Check vendor support and patch status',
              'recommendation': 'Apply vendor-supported updates'}
    review.update(changes)
    response = Mock()
    response.json.return_value = {'response': json.dumps(review)}
    return response


class NmapParserTests(SimpleTestCase):
    def test_sample_metadata(self):
        hosts = parse_nmap_xml(SAMPLE)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0]['ip'], '127.0.0.1')
        services = hosts[0]['services']
        self.assertEqual([s['port'] for s in services], [22, 631])
        self.assertEqual(services[0]['product'], 'OpenSSH')
        self.assertEqual(services[0]['version'], '9.6p1 Ubuntu 3ubuntu13.16')
        self.assertIn('cpe:/a:openbsd:openssh:9.6p1', services[0]['cpe'])
        self.assertEqual(services[1]['product'], 'CUPS')
        self.assertEqual(services[1]['version'], '2.4')

    def test_invalid_and_empty_inputs(self):
        bad_inputs = [b'', b'<nmaprun>', b'<other/>', b'<nmaprun/>',
                      b'<nmaprun><host><status state="down"/></host></nmaprun>',
                      b'<nmaprun><host/></nmaprun>',
                      b'<nmaprun><host><status state="up"/></host></nmaprun>']
        for xml in bad_inputs:
            with self.subTest(xml=xml), self.assertRaises(ValueError):
                parse_nmap_xml(BytesIO(xml))

    def test_invalid_host_port_and_protocol(self):
        for host in [HOST.replace('192.0.2.1', 'invalid'),
                     HOST.replace('portid="22"', 'portid="abc"'),
                     HOST.replace('portid="22"', 'portid="65536"'),
                     HOST.replace('protocol="tcp"', 'protocol="invalid"'),
                     HOST + HOST]:
            with self.subTest(host=host), self.assertRaises(ValueError):
                parse_nmap_xml(BytesIO(('<nmaprun>' + host + '</nmaprun>').encode()))

    def test_ipv6_and_closed_ports(self):
        host = HOST.replace('192.0.2.1', '::1').replace('addrtype="ipv4"', 'addrtype="ipv6"')
        host = host.replace('state="open"', 'state="closed"')
        result = parse_nmap_xml(BytesIO(('<nmaprun>' + host + '</nmaprun>').encode()))
        self.assertEqual(result[0]['ip'], '::1')
        self.assertEqual(result[0]['services'], [])


class ImportTests(TestCase):
    def test_sample_counts_and_relations(self):
        response = self.client.post('/api/upload-log/', {'project_name': 'Sample', 'nmap_file': upload_file()})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(TestProject.objects.count(), 1)
        self.assertEqual(SecurityScan.objects.count(), 1)
        self.assertEqual(TargetAsset.objects.count(), 1)
        self.assertEqual(Service.objects.count(), 2)
        scan = SecurityScan.objects.get()
        asset = scan.assets.get()
        self.assertEqual(scan.status, SecurityScan.Status.COMPLETED)
        self.assertEqual(scan.scan_method, 'nmap-import')
        self.assertEqual(scan.target, '127.0.0.1')
        self.assertEqual(asset.project, scan.project)
        self.assertEqual(asset.services.get(port=22).product, 'OpenSSH')

    def test_invalid_import_creates_nothing(self):
        for data in [b'<nmaprun>', b'<nmaprun/>', b'<wrong/>',
                     b'<nmaprun><host><status state="down"/></host></nmaprun>']:
            with self.subTest(data=data):
                response = self.client.post('/api/upload-log/', {'nmap_file': upload_file(data)})
                self.assertEqual(response.status_code, 400)
                for model in (TestProject, SecurityScan, TargetAsset, Service, SecurityFinding):
                    self.assertEqual(model.objects.count(), 0)

    def test_missing_file(self):
        self.assertEqual(self.client.post('/api/upload-log/').status_code, 400)
        self.assertEqual(TestProject.objects.count(), 0)

    def test_save_failure_rolls_back_everything(self):
        with patch('analyzer.views.Service.save', side_effect=RuntimeError('Storage failure')):
            with self.assertRaises(RuntimeError):
                import_nmap_file(upload_file())
        for model in (TestProject, SecurityScan, TargetAsset, Service):
            self.assertFalse(model.objects.exists())

    def test_existing_project_and_repeated_imports(self):
        project = TestProject.objects.create(name='Existing')
        first = import_nmap_file(upload_file(), project)
        second = import_nmap_file(upload_file(), project)
        self.assertNotEqual(first.pk, second.pk)
        self.assertEqual(TestProject.objects.count(), 1)
        self.assertEqual(project.scans.count(), 2)
        self.assertEqual(project.assets.count(), 2)

    def test_tcp_udp_same_port(self):
        host = HOST.replace('</ports>', '<port protocol="udp" portid="22">'
                            '<state state="open"/></port></ports>')
        scan = import_nmap_file(upload_file(('<nmaprun>' + host + '</nmaprun>').encode()))
        self.assertSetEqual(set(scan.assets.get().services.values_list('protocol', flat=True)), {'tcp', 'udp'})

    def test_invalid_service_length_rolls_back(self):
        host = HOST.replace('product="OpenSSH"', 'product="' + 'a' * 101 + '"')
        response = self.client.post('/api/upload-log/', {
            'nmap_file': upload_file(('<nmaprun>' + host + '</nmaprun>').encode())})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(TestProject.objects.exists())


@override_settings(OLLAMA_URL='http://ollama.test/api/generate', OLLAMA_MODEL='test-model')
class AnalysisTests(TestCase):
    def setUp(self):
        self.scan = import_nmap_file(upload_file())

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post')
    def test_completed_partial_failed(self, post, chroma):
        chroma.return_value.get_collection.side_effect = RuntimeError('Offline')
        for outcomes, status, count in [
            ([ai_response(), ai_response()], SecurityScan.Status.COMPLETED, 2),
            ([ai_response(), requests.ConnectionError()], SecurityScan.Status.PARTIAL, 1),
            ([requests.ConnectionError(), requests.ConnectionError()], SecurityScan.Status.FAILED, 0),
        ]:
            with self.subTest(status=status):
                SecurityFinding.objects.all().delete()
                post.side_effect = outcomes
                result = analyze_scan(self.scan)
                self.scan.refresh_from_db()
                self.assertEqual(self.scan.status, status)
                self.assertEqual(result['status'], status)
                self.assertEqual(len(result['errors']), 2 - count)
                self.assertIsNotNone(self.scan.finished_at)
                self.assertEqual(SecurityFinding.objects.count(), count)
                for finding in SecurityFinding.objects.all():
                    self.assertEqual(finding.asset, finding.service.asset)
                    self.assertEqual(finding.scan, self.scan)
                    self.assertEqual(finding.confidence, SecurityFinding.Confidence.LLM_SUGGESTED)
                    self.assertIn('IP=127.0.0.1', finding.evidence)
        self.assertEqual(post.call_args.args[0], 'http://ollama.test/api/generate')
        self.assertEqual(post.call_args.kwargs['json']['model'], 'test-model')

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post')
    def test_rag_confidence_requires_matching_version_and_returned_cve(self, post, chroma):
        collection = chroma.return_value.get_collection.return_value
        collection.query.return_value = {
            'documents': [['CVE-2024-12345: OpenSSH advisory']],
            'metadatas': [[{'cve_id': 'CVE-2024-12345', 'product': 'OpenSSH', 'version': '9.6p1'}]],
        }
        post.return_value = ai_response(related_cve=['CVE-2024-12345'])
        analyze_scan(self.scan)
        ssh = self.scan.findings.get(service__port=22)
        cups = self.scan.findings.get(service__port=631)
        self.assertEqual(ssh.confidence, SecurityFinding.Confidence.VERSION_INFERRED)
        self.assertEqual(cups.confidence, SecurityFinding.Confidence.LLM_SUGGESTED)
        analyze_scan(self.scan)
        self.assertEqual(self.scan.findings.count(), 2)

    def test_semantic_similarity_and_version_mismatch_do_not_confirm_cve(self):
        service = Service.objects.get(port=22)
        for metadata in [{}, {'product': 'OpenSSH', 'version': '1.0'},
                         {'product': 'Other', 'version': '9.6p1'}]:
            with self.subTest(metadata=metadata):
                records = [('CVE-2024-12345: OpenSSH 9.6p1', metadata, 'collection_cve')]
                self.assertEqual(matching_cves(service, records), set())
        records = [('CVE-2024-12345', {'cpe': 'cpe:/a:openbsd:openssh:9.6p1'}, 'collection_cve')]
        self.assertEqual(matching_cves(service, records), {'CVE-2024-12345'})

    @patch('analyzer.analysis.get_chroma_client', side_effect=RuntimeError('Offline'))
    @patch('analyzer.analysis.requests.post')
    def test_invalid_ai_json_and_fields_fail_without_findings(self, post, chroma):
        invalid = [ai_response(severity='unknown'), ai_response(related_cve='CVE-2024-12345'),
                   ai_response(related_cve=['not-a-cve']), ai_response(description='```blocked```'),
                   ai_response(unexpected='extra')]
        malformed = Mock()
        malformed.json.return_value = {'response': '{'}
        invalid.append(malformed)
        for response in invalid:
            with self.subTest(response=response):
                post.return_value = response
                self.assertEqual(analyze_scan(self.scan)['status'], SecurityScan.Status.FAILED)
                self.assertFalse(SecurityFinding.objects.exists())

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post', side_effect=requests.Timeout)
    def test_api_does_not_report_success_on_failure(self, post, chroma):
        asset = self.scan.assets.get()
        response = self.client.post(f'/api/analyze-asset/{asset.pk}/')
        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.json()['status'], SecurityScan.Status.FAILED)

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post')
    def test_asset_endpoint_reviews_entire_scan(self, post, chroma):
        extra = TargetAsset.objects.create(scan=self.scan, project=self.scan.project, ip_address='192.0.2.2')
        Service.objects.create(asset=extra, port=80, service_name='http')
        post.side_effect = [ai_response(), ai_response(), requests.Timeout()]
        response = self.client.post(f'/api/analyze-asset/{self.scan.assets.first().pk}/')
        self.assertEqual(response.json()['status'], SecurityScan.Status.PARTIAL)
        self.assertEqual(response.json()['reviewed'], 2)


class ChatTests(TestCase):
    def setUp(self):
        self.scan = import_nmap_file(upload_file())
        self.asset = self.scan.assets.get()
        self.url = f'/api/chat-asset/{self.asset.pk}/'

    @patch('analyzer.views.requests.post')
    def test_defensive_chat_context_and_response(self, post):
        SecurityFinding.objects.create(scan=self.scan, asset=self.asset,
            service=self.asset.services.get(port=22), title='SSH support review',
            related_cve=['CVE-2024-12345'], recommendation='Apply vendor update')
        post.return_value.json.return_value = {'response': json.dumps({'reply': 'Review vendor updates.'})}
        response = self.client.post(self.url, data=json.dumps({'message': 'What needs review?'}),
                                    content_type='application/json')
        self.assertEqual(response.json()['reply'], 'Review vendor updates.')
        prompt = post.call_args.kwargs['json']['prompt']
        for text in ('OpenSSH', 'SSH support review', 'CVE-2024-12345', 'Không hướng dẫn khai thác'):
            self.assertIn(text, prompt)

    def test_invalid_chat_requests(self):
        for data in ['{', '[]', '{}', '{"message":12}', '{"message":""}']:
            with self.subTest(data=data):
                self.assertEqual(self.client.post(self.url, data=data,
                    content_type='application/json').status_code, 400)
        self.assertEqual(self.client.get(self.url).status_code, 405)

    @patch('analyzer.views.requests.post')
    def test_failed_or_unexpected_response_is_not_displayed(self, post):
        for result in [{'reply': '```blocked```'}, {'reply': 'Text', 'extra': 'Text'}, ['Text']]:
            post.return_value.json.return_value = {'response': json.dumps(result)}
            response = self.client.post(self.url, data='{"message":"Review?"}', content_type='application/json')
            self.assertEqual(response.status_code, 502)
            self.assertNotIn('blocked', response.content.decode())
        post.side_effect = requests.ConnectionError()
        self.assertEqual(self.client.post(self.url, data='{"message":"Review?"}',
            content_type='application/json').status_code, 502)

    def test_csrf_is_required(self):
        response = Client(enforce_csrf_checks=True).post(self.url,
            data='{"message":"Review?"}', content_type='application/json')
        self.assertEqual(response.status_code, 403)


class ProjectInterfaceTests(TestCase):
    def test_project_creation_and_sample_import_redirect(self):
        response = self.client.post('/', {'name': 'Browser project', 'target_url': 'http://localhost/',
            'description': 'Review', 'allowed_hosts': '127.0.0.1\n'})
        project = TestProject.objects.get()
        self.assertRedirects(response, f'/projects/{project.pk}/')
        self.assertContains(self.client.get(f'/projects/{project.pk}/'), 'Chưa có test case')
        self.assertContains(self.client.get(f'/projects/{project.pk}/?tab=security'), 'Recon tự động')
        response = self.client.post(f'/projects/{project.pk}/import/', {'nmap_file': upload_file()}, follow=True)
        scan = project.scans.get()
        self.assertEqual(response.redirect_chain, [(f'/scans/{scan.pk}/', 302)])
        for text in ('Đã nhập kết quả Nmap.', 'OpenSSH', 'CUPS', 'COMPLETED'):
            self.assertContains(response, text)
        self.assertEqual(TestProject.objects.count(), 1)

    def test_invalid_browser_import_renders_errors_and_no_scan(self):
        project = TestProject.objects.create(name='Existing')
        response = self.client.post(f'/projects/{project.pk}/import/', {'nmap_file': upload_file(b'<nmaprun>')})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(SecurityScan.objects.exists())
        self.assertFalse(TargetAsset.objects.exists())
        self.assertFalse(Service.objects.exists())
        self.assertEqual(TestProject.objects.count(), 1)

    def test_invalid_project_form_and_missing_file(self):
        self.assertEqual(self.client.post('/', {'name': '', 'target_url': 'invalid'}).status_code, 400)
        self.assertFalse(TestProject.objects.exists())
        project = TestProject.objects.create(name='Existing')
        self.assertEqual(self.client.post(f'/projects/{project.pk}/import/').status_code, 400)
        self.assertFalse(SecurityScan.objects.exists())

    def test_functional_tab_and_finding_display_are_escaped(self):
        scan = import_nmap_file(upload_file())
        FunctionalTestCase.objects.create(project=scan.project, name='Login test',
                                           steps=[{'no': 1, 'action': 'Open login', 'expected': 'Login page'}])
        self.assertContains(self.client.get(f'/projects/{scan.project_id}/'), 'Login test')
        asset = scan.assets.get()
        finding = SecurityFinding.objects.create(scan=scan, asset=asset,
            service=asset.services.get(port=22), title='Support review', severity='high',
            confidence='version_inferred', evidence='<script>untrusted</script>',
            related_cve=['CVE-2024-12345'], recommendation='Apply vendor updates')
        response = self.client.get(f'/scans/{scan.pk}/')
        for text in ('Support review', 'CVE-2024-12345', 'Apply vendor updates',
                     finding.get_confidence_display(), finding.get_severity_display()):
            self.assertContains(response, text)
        self.assertContains(response, '&lt;script&gt;untrusted&lt;/script&gt;')
        detail = self.client.get(f'/api/get-asset-detail/{asset.pk}/').json()
        self.assertEqual(detail['services'][0]['findings'][0]['title'], 'Support review')

    @patch('analyzer.analysis.get_chroma_client')
    @patch('analyzer.analysis.requests.post')
    def test_browser_analysis_failure_reports_actual_status(self, post, chroma):
        scan = import_nmap_file(upload_file())
        post.side_effect = [ai_response(), requests.Timeout()]
        response = self.client.post(f'/scans/{scan.pk}/analyze/', follow=True)
        self.assertContains(response, 'PARTIAL')
        self.assertContains(response, '1 dịch vụ đánh giá lỗi')
        self.assertNotContains(response, 'Đánh giá rủi ro hoàn tất.')

    def test_unknown_project_and_scan_return_404(self):
        self.assertEqual(self.client.get('/projects/999/').status_code, 404)
        self.assertEqual(self.client.get('/scans/999/').status_code, 404)


class ModelAndAdminTests(TestCase):
    def test_allowed_hosts_trims_whitespace_and_ignores_empty_lines(self):
        project = TestProject(name='Scope', allowed_hosts=' example.com \r\n\n 127.0.0.1 \n192.0.2.0/24\n\t')
        self.assertEqual(project.get_allowed_hosts(), ['example.com', '127.0.0.1', '192.0.2.0/24'])
        self.assertEqual(TestProject(name='Empty').get_allowed_hosts(), [])

    def test_functional_relationships_and_step_order(self):
        project = TestProject.objects.create(name='Functional')
        case = FunctionalTestCase.objects.create(project=project, name='Login', steps=[])
        run = FunctionalTestRun.objects.create(test_case=case)
        TestStepResult.objects.create(run=run, step_no=2, action='Read result')
        TestStepResult.objects.create(run=run, step_no=1, action='Open page')
        self.assertEqual(list(run.steps.values_list('step_no', flat=True)), [1, 2])
        self.assertEqual(project.test_cases.get(), case)
        project.delete()
        self.assertFalse(FunctionalTestRun.objects.exists())
        self.assertFalse(TestStepResult.objects.exists())

    def test_all_models_registered(self):
        for model in (TestProject, FunctionalTestCase, FunctionalTestRun, TestStepResult,
                      SecurityScan, TargetAsset, Service, SecurityFinding):
            with self.subTest(model=model.__name__):
                self.assertTrue(admin.site.is_registered(model))
