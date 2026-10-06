import xml.etree.ElementTree as ET
from ipaddress import ip_address

def parse_nmap_xml(nmap_file):
    """
    Parse file Nmap XML (nhận cả file path dạng string hoặc InMemoryUploadedFile từ Django)
    """
    hosts_data = []
    
    try:
        # ElementTree có thể parse trực tiếp file-like object từ Django request.FILES
        tree = ET.parse(nmap_file)
        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ValueError("File XML không phải kết quả quét Nmap (thiếu nmaprun).")
        
        for host in root.findall('host'):
            # Kiểm tra trạng thái máy (Up/Down)
            status = host.find('status')
            if status is not None and status.get('state') != 'up':
                continue
                
            # Lấy IP Address
            ip_addr = "0.0.0.0"
            address = host.find('address[@addrtype="ipv4"]')
            if address is not None:
                ip_addr = address.get('addr', '0.0.0.0')
            elif host.find('address') is not None:
                ip_addr = host.find('address').get('addr', '0.0.0.0')
                
            try:
                ip_address(ip_addr)
            except ValueError as exc:
                raise ValueError("Địa chỉ IP của máy mục tiêu không hợp lệ.") from exc
            if host.find("address") is None:
                raise ValueError("Máy mục tiêu thiếu địa chỉ IP.")

            # Lấy Hostname
            hostname = ""
            hostnames = host.find('hostnames')
            if hostnames is not None:
                hn = hostnames.find('hostname')
                if hn is not None:
                    hostname = hn.get('name', '')
                    
            # Lấy Hệ điều hành (OS)
            os_info = "Unknown OS"
            os_elem = host.find('os/osmatch')
            if os_elem is not None:
                os_info = os_elem.get('name', 'Unknown OS')
                
            # Bóc tách danh sách cổng & dịch vụ
            services = []
            ports = host.find('ports')
            if ports is not None:
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        try:
                            port_id = int(port.get('portid', ''))
                        except ValueError as exc:
                            raise ValueError("Số cổng trong XML Nmap không hợp lệ.") from exc
                        if not 0 <= port_id <= 65535:
                            raise ValueError("Số cổng phải nằm trong khoảng 0–65535.")
                        service_elem = port.find('service')
                        
                        service_name = "unknown"
                        service_version = ""
                        
                        if service_elem is not None:
                            service_name = service_elem.get('name', 'unknown')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            extrainfo = service_elem.get('extrainfo', '')
                            
                            service_version = f"{product} {version} {extrainfo}".strip()
                            
                        services.append({
                            'port': port_id,
                            'name': service_name,
                            'version': service_version
                        })
                        
            hosts_data.append({
                'ip': ip_addr,
                'hostname': hostname,
                'os': os_info,
                'services': services
            })
            
    except ET.ParseError as exc:
        raise ValueError("File XML không hợp lệ hoặc bị hỏng.") from exc
        
    if not hosts_data:
        raise ValueError("File Nmap XML không chứa máy mục tiêu đang hoạt động.")
    return hosts_data
