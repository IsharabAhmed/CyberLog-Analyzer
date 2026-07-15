"""
URL configuration for the analytics app.

Routes:
    /alerts/                        - List all alerts (with filters)
    /alerts/<uuid:pk>/resolve/      - Toggle alert resolved status
"""

from django.urls import path

from .views import alert_list_view, alert_resolve_view

app_name = 'analytics'

urlpatterns = [
    path('alerts/', alert_list_view, name='alerts'),
    path('alerts/<uuid:pk>/resolve/', alert_resolve_view, name='alert-resolve'),
]
