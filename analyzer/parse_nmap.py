import xml.etree.ElementTree as ET

def parse_nmap_xml(nmap_file):
    """
    Parse file Nmap XML (nhận cả file path dạng string hoặc InMemoryUploadedFile từ Django)
    """
    hosts_data = []
    
    try:
        # ElementTree có thể parse trực tiếp file-like object từ Django request.FILES
        tree = ET.parse(nmap_file)
        root = tree.getroot()
        
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
                        port_id = int(port.get('portid', 0))
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
            
    except Exception as e:
        print(f"❌ Lỗi trong quá trình parse Nmap XML: {e}")
        
    return hosts_data