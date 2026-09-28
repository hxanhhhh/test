from django.db import models
from django.contrib.auth.models import User

class SecurityProject(models.Model):
    """Quản lý từng Chiến dịch / Dự án Pentest"""
    name = models.CharField(max_length=255, verbose_name="Tên dự án")
    description = models.TextField(blank=True, null=True, verbose_name="Mô tả dự án")
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    def __str__(self):
        return self.name

class TargetAsset(models.Model):
    """Lưu trữ từng Máy mục tiêu (IP / Host) thuộc dự án"""
    project = models.ForeignKey(SecurityProject, related_name="assets", on_delete=models.CASCADE)
    ip_address = models.CharField(max_length=50, verbose_name="Địa chỉ IP")
    hostname = models.CharField(max_length=255, blank=True, null=True, verbose_name="Host Name")
    os_info = models.CharField(max_length=255, blank=True, null=True, verbose_name="Hệ điều hành")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.project.name})"

class ExploitSuggestion(models.Model):
    """Lưu danh sách Cổng/Dịch vụ, Mã PoC và Chuỗi tấn công AI sinh ra"""
    asset = models.ForeignKey(TargetAsset, related_name="vulnerabilities", on_delete=models.CASCADE)
    port = models.IntegerField(verbose_name="Cổng")
    service_name = models.CharField(max_length=100, verbose_name="Dịch vụ")
    service_version = models.CharField(max_length=100, blank=True, null=True, verbose_name="Phiên bản")
    
    attack_path_summary = models.TextField(verbose_name="Chuỗi tấn công (Attack Path)")
    suggested_poc_code = models.TextField(verbose_name="Mã kiểm thử Exploit (Python)")
    cve_references = models.CharField(max_length=255, blank=True, null=True, verbose_name="Mã CVE")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Port {self.port} - {self.asset.ip_address}"