from analyzer.views import generate_security_report
from django.urls import path
from . import views

urlpatterns = [
    path('report/export/', views.generate_security_report, name='export_report'),
    path('', views.dashboard_view, name='dashboard'),
    path('projects/<int:project_id>/', views.project_detail, name='project_detail'),
    path('projects/<int:project_id>/import/', views.project_import_nmap, name='project_import_nmap'),
    path('projects/<int:project_id>/recon/', views.project_recon, name='project_recon'),
    path('scans/<int:scan_id>/', views.scan_detail, name='scan_detail'),
    path('scans/<int:scan_id>/analyze/', views.scan_analyze, name='scan_analyze'),
    path('api/upload-log/', views.upload_nmap_log, name='upload_log'),
    path('api/analyze-asset/<int:asset_id>/', views.analyze_target_asset, name='analyze_asset'),
    path('api/get-asset-detail/<int:asset_id>/', views.get_asset_detail, name='get_asset_detail'),
    path('api/chat-asset/<int:asset_id>/', views.chat_with_asset_ai, name='chat_asset'),
    path('api/kali-status/', views.kali_status, name='kali_status'),
    path('projects/<int:project_id>/pentest/', views.project_pentest, name='project_pentest'),
    path('api/kali-pentest/', views.kali_pentest_api, name='kali_pentest_api'),
]
