from django.db import models
from django.contrib.auth.models import User


# ---------------------------------------------------------------------------
# Chung
# ---------------------------------------------------------------------------

class TestProject(models.Model):
    """Một website/hệ thống cần kiểm thử (dùng cho cả Functional và Security)"""
    name = models.CharField(max_length=255, verbose_name="Tên dự án")
    target_url = models.URLField(blank=True, verbose_name="URL mục tiêu")
    description = models.TextField(blank=True, verbose_name="Mô tả / yêu cầu kiểm thử")
    allowed_hosts = models.TextField(
        blank=True,
        verbose_name="Phạm vi cho phép",
        help_text="Mỗi dòng một host/IP/CIDR. Security tool chỉ được quét trong danh sách này.",
    )
    created_at = models.DateTimeField(auto_now_add=True, verbose_name="Ngày tạo")
    owner = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)

    def get_allowed_hosts(self):
        return [h.strip() for h in self.allowed_hosts.splitlines() if h.strip()]

    def __str__(self):
        return self.name


# ---------------------------------------------------------------------------
# Functional Web Testing
# ---------------------------------------------------------------------------

class FunctionalTestCase(models.Model):
    """Test case do AI sinh hoặc người dùng tự viết"""

    class Source(models.TextChoices):
        AI = "ai", "AI sinh"
        MANUAL = "manual", "Tự viết"

    project = models.ForeignKey(TestProject, related_name="test_cases", on_delete=models.CASCADE)
    name = models.CharField(max_length=255, verbose_name="Tên test case")
    # [{"no": 1, "action": "...", "expected": "..."}]
    steps = models.JSONField(default=list, verbose_name="Các bước")
    expected_result = models.TextField(blank=True, verbose_name="Kết quả mong đợi")
    source = models.CharField(max_length=10, choices=Source.choices, default=Source.AI)
    approved = models.BooleanField(default=False, verbose_name="Đã duyệt để chạy")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


class FunctionalTestRun(models.Model):
    """Một lần chạy test case"""

    class Status(models.TextChoices):
        PENDING = "PENDING", "Chờ chạy"
        RUNNING = "RUNNING", "Đang chạy"
        PASS = "PASS", "Đạt"
        FAIL = "FAIL", "Không đạt"
        ERROR = "ERROR", "Lỗi hệ thống"

    test_case = models.ForeignKey(FunctionalTestCase, related_name="runs", on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    actual_result = models.TextField(blank=True, verbose_name="Kết quả thực tế")
    model_name = models.CharField(max_length=100, blank=True, verbose_name="Model LLM đã dùng")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Run #{self.pk} - {self.test_case.name} [{self.status}]"


class TestStepResult(models.Model):
    """Vết từng hành động của Agent trong một lần chạy"""

    class Status(models.TextChoices):
        PASS = "PASS", "Đạt"
        FAIL = "FAIL", "Không đạt"
        ERROR = "ERROR", "Lỗi"

    run = models.ForeignKey(FunctionalTestRun, related_name="steps", on_delete=models.CASCADE)
    step_no = models.PositiveIntegerField()
    action = models.TextField(verbose_name="Mô tả hành động")
    tool = models.CharField(max_length=100, blank=True, verbose_name="MCP tool")
    input = models.JSONField(default=dict, blank=True)
    result = models.JSONField(default=dict, blank=True)
    screenshot = models.CharField(max_length=500, blank=True, verbose_name="Đường dẫn ảnh")
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PASS)
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["run", "step_no"]
        unique_together = [("run", "step_no")]

    def __str__(self):
        return f"Run #{self.run_id} - step {self.step_no} ({self.tool})"


# ---------------------------------------------------------------------------
# Security Testing
# ---------------------------------------------------------------------------

class SecurityScan(models.Model):
    """Một phiên security testing"""

    class Status(models.TextChoices):
        PENDING = "PENDING", "Chờ chạy"
        RUNNING = "RUNNING", "Đang chạy"
        COMPLETED = "COMPLETED", "Hoàn tất"
        PARTIAL = "PARTIAL", "Hoàn tất một phần"
        FAILED = "FAILED", "Thất bại"

    project = models.ForeignKey(TestProject, related_name="scans", on_delete=models.CASCADE)
    target = models.CharField(max_length=255, verbose_name="Mục tiêu quét")
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PENDING)
    scan_method = models.CharField(max_length=50, blank=True, help_text="Ví dụ: nmap, nmap-import")
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Scan #{self.pk} - {self.target} [{self.status}]"


class TargetAsset(models.Model):
    """Máy mục tiêu (IP / Host) thuộc dự án, có thể gắn với một lần quét"""
    project = models.ForeignKey(TestProject, related_name="assets", on_delete=models.CASCADE)
    scan = models.ForeignKey(SecurityScan, related_name="assets", on_delete=models.SET_NULL,
                             null=True, blank=True)
    ip_address = models.CharField(max_length=50, verbose_name="Địa chỉ IP")
    hostname = models.CharField(max_length=255, blank=True, null=True, verbose_name="Host Name")
    os_info = models.CharField(max_length=255, blank=True, null=True, verbose_name="Hệ điều hành")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} ({self.project.name})"


class Service(models.Model):
    """Cổng / dịch vụ mở trên một máy (kết quả Nmap), tách khỏi phần kết luận của AI"""
    asset = models.ForeignKey(TargetAsset, related_name="services", on_delete=models.CASCADE)
    port = models.IntegerField(verbose_name="Cổng")
    protocol = models.CharField(max_length=10, default="tcp")
    service_name = models.CharField(max_length=100, blank=True, verbose_name="Dịch vụ")
    product = models.CharField(max_length=100, blank=True, verbose_name="Sản phẩm")
    service_version = models.CharField(max_length=100, blank=True, null=True, verbose_name="Phiên bản")
    cpe = models.CharField(max_length=255, blank=True, verbose_name="CPE")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["port"]
        unique_together = [("asset", "port", "protocol")]

    def __str__(self):
        return f"{self.asset.ip_address}:{self.port}/{self.protocol} {self.service_name}"


class SecurityFinding(models.Model):
    """Phát hiện bảo mật kèm bằng chứng và khuyến nghị"""

    class Severity(models.TextChoices):
        INFO = "info", "Thông tin"
        LOW = "low", "Thấp"
        MEDIUM = "medium", "Trung bình"
        HIGH = "high", "Cao"
        CRITICAL = "critical", "Nghiêm trọng"

    class Confidence(models.TextChoices):
        TOOL_VERIFIED = "tool_verified", "Công cụ xác nhận"
        VERSION_INFERRED = "version_inferred", "Suy ra từ phiên bản"
        LLM_SUGGESTED = "llm_suggested", "AI đề xuất (cần xác minh)"

    scan = models.ForeignKey(SecurityScan, related_name="findings", on_delete=models.CASCADE)
    asset = models.ForeignKey(TargetAsset, related_name="findings", on_delete=models.CASCADE,
                              null=True, blank=True)
    service = models.ForeignKey(Service, related_name="findings", on_delete=models.SET_NULL,
                                null=True, blank=True)
    title = models.CharField(max_length=255)
    category = models.CharField(max_length=100, blank=True,
                                help_text="Ví dụ: outdated_service, missing_header, weak_tls")
    severity = models.CharField(max_length=10, choices=Severity.choices, default=Severity.INFO)
    confidence = models.CharField(max_length=20, choices=Confidence.choices,
                                  default=Confidence.LLM_SUGGESTED)
    evidence = models.TextField(blank=True, verbose_name="Bằng chứng")
    related_cve = models.JSONField(default=list, blank=True, verbose_name="CVE liên quan")
    description = models.TextField(blank=True)
    recommendation = models.TextField(blank=True, verbose_name="Khuyến nghị")
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"[{self.severity}] {self.title}"
