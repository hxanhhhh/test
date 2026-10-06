from django.contrib import admin

from .models import (TestProject, FunctionalTestCase, FunctionalTestRun,
                     TestStepResult, SecurityScan, TargetAsset, Service, SecurityFinding)


@admin.register(TestProject)
class TestProjectAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'target_url', 'owner', 'created_at')
    search_fields = ('name', 'target_url')


@admin.register(FunctionalTestCase)
class FunctionalTestCaseAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'project', 'source', 'approved')
    list_filter = ('source', 'approved')


@admin.register(FunctionalTestRun)
class FunctionalTestRunAdmin(admin.ModelAdmin):
    list_display = ('id', 'test_case', 'status', 'model_name', 'started_at', 'finished_at')
    list_filter = ('status',)


@admin.register(TestStepResult)
class TestStepResultAdmin(admin.ModelAdmin):
    list_display = ('id', 'run', 'step_no', 'tool', 'status', 'duration_ms')
    list_filter = ('status',)


@admin.register(SecurityScan)
class SecurityScanAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'target', 'scan_method', 'status', 'created_at')
    list_filter = ('status', 'scan_method')


@admin.register(TargetAsset)
class TargetAssetAdmin(admin.ModelAdmin):
    list_display = ('id', 'project', 'scan', 'ip_address', 'hostname')
    search_fields = ('ip_address', 'hostname')


@admin.register(Service)
class ServiceAdmin(admin.ModelAdmin):
    list_display = ('id', 'asset', 'port', 'protocol', 'service_name', 'product', 'service_version')
    list_filter = ('protocol', 'service_name')


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):
    list_display = ('id', 'scan', 'asset', 'service', 'title', 'category', 'severity', 'confidence')
    list_filter = ('severity', 'confidence', 'category')
