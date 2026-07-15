"""
URL configuration for Cybersecurity Log Analysis Platform.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.shortcuts import redirect

urlpatterns = [
    path('admin/', admin.site.urls),
    path('accounts/', include('apps.accounts.urls', namespace='accounts')),
    path('logs/', include('apps.logs.urls', namespace='logs')),
    path('analytics/', include('apps.analytics.urls', namespace='analytics')),
    path('dashboard/', include('apps.dashboard.urls', namespace='dashboard')),
    path('', lambda request: redirect('dashboard:overview')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
