from django.contrib import admin
from django.urls import path
from dashboard.views import dashboard_view
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', dashboard_view, name='dashboard'),
]

# Cho phép Django hiển thị ảnh evidence trong môi trường dev
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
