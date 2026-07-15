"""
Account views for user registration, authentication, and profile management.

Handles user lifecycle: registration, login, logout, and a profile dashboard
showing upload statistics (total uploads, entries, alerts, recent files).
"""

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView, LogoutView

from apps.logs.models import LogEntry
from apps.analytics.models import Alert

from .forms import RegisterForm, LoginForm


def register_view(request):
    """
    Handle user registration.

    GET: Display the registration form.
    POST: Validate and create a new user account, then redirect to login.
    """
    if request.user.is_authenticated:
        return redirect('dashboard:overview')

    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                messages.success(
                    request,
                    f'Account created successfully for {user.username}. Please log in.',
                )
                return redirect('accounts:login')
            except Exception as e:
                messages.error(request, f'An error occurred during registration: {str(e)}')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{error}')
    else:
        form = RegisterForm()

    return render(request, 'accounts/register.html', {'form': form})


class CustomLoginView(LoginView):
    """
    Custom login view using the styled LoginForm.

    Redirects authenticated users to the dashboard. On successful login,
    redirects to the 'next' parameter or dashboard overview.
    """

    template_name = 'accounts/login.html'
    authentication_form = LoginForm
    redirect_authenticated_user = True

    def get_success_url(self):
        """Return the URL to redirect to after login."""
        return self.request.GET.get('next', '/dashboard/')

    def form_invalid(self, form):
        """Add an error message when login fails."""
        messages.error(self.request, 'Invalid username or password.')
        return super().form_invalid(form)


class CustomLogoutView(LogoutView):
    """
    Custom logout view that redirects to the login page.
    """

    next_page = '/accounts/login/'

    def dispatch(self, request, *args, **kwargs):
        """Add a success message on logout."""
        messages.info(request, 'You have been logged out successfully.')
        return super().dispatch(request, *args, **kwargs)


@login_required
def profile_view(request):
    """
    Display the user's profile with upload statistics.

    Shows:
    - Total number of uploaded log files
    - Total parsed log entries across all uploads
    - Total alerts generated from the user's files
    - The 5 most recent uploads
    """
    user = request.user

    try:
        total_uploads = user.log_files.count()
        total_entries = LogEntry.objects.filter(log_file__user=user).count()
        total_alerts = Alert.objects.filter(log_file__user=user).count()
        recent_uploads = user.log_files.all().order_by('-uploaded_at')[:5]
    except Exception as e:
        messages.error(request, f'Error loading profile data: {str(e)}')
        total_uploads = 0
        total_entries = 0
        total_alerts = 0
        recent_uploads = []

    context = {
        'total_uploads': total_uploads,
        'total_entries': total_entries,
        'total_alerts': total_alerts,
        'recent_uploads': recent_uploads,
    }

    return render(request, 'accounts/profile.html', context)
