"""Read Nmap results without executing network operations."""
from ipaddress import ip_address
import xml.etree.ElementTree as ET
from analyzer.models import TargetAsset, Service

def parse_nmap_xml(nmap_file):
    try:
        root = ET.parse(nmap_file).getroot()
    except ET.ParseError as exc:
        raise ValueError('File XML không hợp lệ hoặc bị hỏng.') from exc
    if root.tag != 'nmaprun':
        raise ValueError('File XML không phải kết quả Nmap.')

    hosts = []
    seen_addresses = set()
    for host in root.findall('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        address = host.find('address[@addrtype="ipv4"]')
        if address is None:
            address = host.find('address[@addrtype="ipv6"]')
        if address is None:
            raise ValueError('Máy mục tiêu thiếu địa chỉ IP.')
        try:
            ip = str(ip_address(address.get('addr', '')))
        except ValueError as exc:
            raise ValueError('Địa chỉ IP không hợp lệ.') from exc
        if ip in seen_addresses:
            raise ValueError('File Nmap chứa máy mục tiêu trùng địa chỉ IP.')
        seen_addresses.add(ip)
        hostname = host.find('hostnames/hostname')
        os_match = host.find('os/osmatch')
        services = []
        seen_ports = set()
        for port in host.findall('ports/port'):
            state = port.find('state')
            if state is None or state.get('state') != 'open':
                continue
            try:
                number = int(port.get('portid', ''))
            except ValueError as exc:
                raise ValueError('Số cổng không hợp lệ.') from exc
            protocol = port.get('protocol', 'tcp')
            if not 0 <= number <= 65535 or protocol not in ('tcp', 'udp', 'sctp'):
                raise ValueError('Cổng hoặc giao thức không hợp lệ.')
            if (number, protocol) in seen_ports:
                raise ValueError('File Nmap chứa cổng/giao thức bị trùng.')
            seen_ports.add((number, protocol))
            element = port.find('service')
            attrs = element.attrib if element is not None else {}
            cpes = [c.text.strip() for c in element.findall('cpe') if c.text] if element is not None else []
            services.append({
                'port': number, 'protocol': protocol,
                'name': attrs.get('name', 'unknown'),
                'product': attrs.get('product', ''),
                'version': attrs.get('version', ''),
                'cpe': '\n'.join(cpes),
            })
        hosts.append({
            'ip': ip,
            'hostname': hostname.get('name', '') if hostname is not None else '',
            'os': os_match.get('name', 'Unknown OS') if os_match is not None else 'Unknown OS',
            'services': services,
        })
    if not hosts:
        raise ValueError('File Nmap không chứa máy mục tiêu đang hoạt động (up).')
    return hosts
def auto_save_and_trigger_rag(target_asset_id, xml_file_path):
    """
    1. Đọc file XML Nmap bằng parse_nmap_xml có sẵn.
    2. Lưu các dịch vụ quét được vào bảng Service trong DB.
    3. Tự động kích hoạt pipeline RAG để đối chiếu CVE.
    """
    try:
        
        parsed_hosts = parse_nmap_xml(xml_file_path)
        target_asset = TargetAsset.objects.get(id=target_asset_id)
        
        saved_count = 0
        for host_data in parsed_hosts:
            
            for s in host_data['services']:
                Service.objects.update_or_create(
                    asset=target_asset,
                    port=s['port'],
                    protocol=s['protocol'],
                    defaults={
                        'service_name': s['name'],
                        'product': s['product'],
                        'service_version': s['version'],
                    
                    }
                )
                saved_count += 1
                
        print(f"[Thành công A] Đã lưu {saved_count} dịch vụ vào bảng Service từ Nmap.")
        
        return True
    except Exception as e:
        print(f"[Lỗi tích hợp Nmap->RAG]: {e}")
        return False
