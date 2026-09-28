from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard_view, name='dashboard'),
    path('api/upload-log/', views.upload_nmap_log, name='upload_log'),
    path('api/analyze-asset/<int:asset_id>/', views.analyze_target_asset, name='analyze_asset'),
    path('api/get-asset-detail/<int:asset_id>/', views.get_asset_detail, name='get_asset_detail'),
    path('api/chat-asset/<int:asset_id>/', views.chat_with_asset_ai, name='chat_asset'), # Route Chatbot
]