from django.contrib import admin
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    # Trang chủ hợp nhất + toàn bộ luồng project/scan/API nằm trong app analyzer.
    path('', include('analyzer.urls')),
]

# Cho phép Django phục vụ ảnh evidence trong môi trường dev
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
