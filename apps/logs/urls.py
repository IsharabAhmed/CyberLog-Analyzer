"""
URL configuration for the logs app.

Routes:
    /upload/        - Upload a new log file
    /               - List all log entries (with search/filter)
    /<uuid:pk>/     - Detail view for a specific log file
"""

from django.urls import path

from .views import upload_view, log_list_view, log_detail_view

app_name = 'logs'

urlpatterns = [
    path('upload/', upload_view, name='upload'),
    path('', log_list_view, name='list'),
    path('<uuid:pk>/', log_detail_view, name='detail'),
]
