"""
URL configuration for the accounts app.

Routes:
    /login/     - User login
    /logout/    - User logout
    /register/  - New user registration
    /profile/   - User profile dashboard
"""

from django.urls import path

from .views import CustomLoginView, CustomLogoutView, register_view, profile_view

app_name = 'accounts'

urlpatterns = [
    path('login/', CustomLoginView.as_view(), name='login'),
    path('logout/', CustomLogoutView.as_view(), name='logout'),
    path('register/', register_view, name='register'),
    path('profile/', profile_view, name='profile'),
]
