import shlex
from io import BytesIO

from analyzer.kali.base import guard, blocked, finding, target_host
from analyzer.models import TargetAsset, Service

try:
    from analyzer.cve_matcher import run_nmap_cve_pipeline
except Exception:  # pragma: no cover
    run_nmap_cve_pipeline = None

try:
    from analyzer.parse_nmap import parse_nmap_xml
except Exception:  # pragma: no cover
    parse_nmap_xml = None


def register(reg, client):
    @reg.tool(name="nmap", title="Nmap – recon cổng/dịch vụ", category="recon_osint",
              description="Quét cổng + nhận diện dịch vụ (-sV). Kết quả XML được đẩy vào RAG-CVE.",
              params=["target"])
    def nmap(target):
        if not guard(target):
            return blocked("nmap", target)
        host = target_host(target)
        cmd = f"nmap -sV -T4 -Pn --top-ports 100 -oX - {shlex.quote(host)}"
        res = client.run(cmd, timeout=360)
        stdout = res.get("stdout", "") or ""
        services, findings = [], []
        if parse_nmap_xml and "<nmaprun" in stdout:
            try:
                for h in parse_nmap_xml(BytesIO(stdout.encode("utf-8", "ignore"))):
                    ip = h["ip"]
                    
                    target_asset, _ = TargetAsset.objects.get_or_create(ip_address=ip)

                    for s in h.get("services", []):
                        services.append({**s, "ip": ip})
                        
                      
                        Service.objects.update_or_create(
                            asset=target_asset,
                            port=s['port'],
                            protocol=s['protocol'],
                            defaults={
                                'service_name': s.get('name', 'unknown'),
                                'product': s.get('product', ''),
                                'service_version': s.get('version', ''),
                            }
                        )

                        findings.append(finding("nmap", "Info",
                            f"Dịch vụ mở {s['port']}/{s['protocol']} {s.get('name','')}",
                            f"{ip}:{s['port']} {s.get('product','')} {s.get('version','')}".strip(),
                            "Đối chiếu phiên bản với CVE (RAG); tắt dịch vụ không cần thiết."))
                
             
                if run_nmap_cve_pipeline:
                    try:
                        run_nmap_cve_pipeline()
                    except Exception:
                        pass

            except Exception:
                pass
        if not findings and stdout:
            findings.append(finding("nmap", "Info", "Kết quả nmap", stdout[:300], "Xem output nmap."))
        return {"ok": res.get("success", False), "tool": "nmap", "command": cmd,
                "services": services, "findings": findings,
                "xml": stdout, "raw": stdout[:4000]}
