"""Lưu kết quả orchestrator (pipeline/agent) vào DB dùng chung với luồng cũ.

Tái dùng các model sẵn có: SecurityScan -> TargetAsset -> SecurityFinding,
nên không cần migration mới và kết quả Kali vào chung báo cáo với luồng nmap/CVE.
"""
from django.utils import timezone

from analyzer.models import SecurityScan, TargetAsset, Service, SecurityFinding

# orchestrator dùng 'Critical/High/Medium/Low/Info' -> model dùng chữ thường.
SEV_MAP = {"critical": SecurityFinding.Severity.CRITICAL,
           "high": SecurityFinding.Severity.HIGH,
           "medium": SecurityFinding.Severity.MEDIUM,
           "low": SecurityFinding.Severity.LOW,
           "info": SecurityFinding.Severity.INFO}


def save_orchestrator_result(project, result):
    """Tạo một SecurityScan từ dict kết quả orchestrator. Trả về scan đã lưu."""
    status = (SecurityScan.Status.COMPLETED if result.get("ok")
              else SecurityScan.Status.PARTIAL)
    now = timezone.now()
    scan = SecurityScan.objects.create(
        project=project, target=result.get("target", "") or "",
        status=status, scan_method=f"kali-{result.get('mode') or 'pipeline'}",
        started_at=now, finished_at=now,
    )
    asset = TargetAsset.objects.create(
        project=project, scan=scan,
        ip_address=result.get("target", "") or "-", hostname="",
    )

    # Dịch vụ từ nmap (nếu có) -> bảng Service, để đối chiếu CVE sau này.
    for s in result.get("services", []) or []:
        try:
            Service.objects.get_or_create(
                asset=asset, port=int(s.get("port") or 0),
                protocol=s.get("protocol", "tcp") or "tcp",
                defaults={
                    "service_name": (s.get("name") or "")[:100],
                    "product": (s.get("product") or "")[:100],
                    "service_version": (s.get("version") or "")[:100] or None,
                },
            )
        except (ValueError, TypeError):
            continue

    # Mỗi finding của mỗi bước -> SecurityFinding (bằng chứng = lệnh + output thô).
    for step in result.get("steps", []) or []:
        tool = step.get("tool", "")
        raw = (step.get("raw") or "")[:2000]
        cmd = step.get("command", "")
        for f in step.get("findings", []) or []:
            sev = (f.get("severity") or "Info").lower()
            SecurityFinding.objects.create(
                scan=scan, asset=asset,
                title=(f.get("title") or tool or "Phát hiện")[:255],
                category=tool[:100],
                severity=SEV_MAP.get(sev, SecurityFinding.Severity.INFO),
                confidence=SecurityFinding.Confidence.TOOL_VERIFIED,
                evidence=(f"$ {cmd}\n{raw}" if cmd else raw)[:4000],
                description=(f.get("description") or "")[:4000],
                recommendation=(f.get("recommendation") or "")[:2000],
            )
    return scan
