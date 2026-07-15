import os

base_dir = r"d:\Code\Portfolio\Projects\Cybersecurity Log Analyzer"

templates_dir = os.path.join(base_dir, "templates")
static_dir = os.path.join(base_dir, "static")

# Create directories
dirs_to_create = [
    os.path.join(templates_dir, "components"),
    os.path.join(templates_dir, "accounts"),
    os.path.join(templates_dir, "logs"),
    os.path.join(templates_dir, "analytics"),
    os.path.join(templates_dir, "dashboard"),
    os.path.join(static_dir, "css"),
    os.path.join(static_dir, "js"),
    os.path.join(static_dir, "images"),
]

for d in dirs_to_create:
    os.makedirs(d, exist_ok=True)

files = {}

files["templates/base.html"] = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{% block title %}CyberLog{% endblock %}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        slate: { 950: '#020617', 900: '#0f172a', 800: '#1e293b', 700: '#334155', 400: '#94a3b8', 100: '#f1f5f9' },
                        emerald: { 500: '#10b981', 600: '#059669' },
                        amber: { 500: '#f59e0b' },
                        red: { 500: '#ef4444' },
                        orange: { 500: '#f97316' },
                        yellow: { 500: '#eab308' },
                        blue: { 500: '#3b82f6' }
                    },
                    fontFamily: {
                        sans: ['Inter', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    }
                }
            }
        }
    </script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://cdn.plot.ly/plotly-2.27.0.min.js"></script>
    <link rel="stylesheet" href="{% static 'css/custom.css' %}">
</head>
<body class="bg-slate-950 text-slate-100 font-sans min-h-screen">
    <div class="flex h-screen overflow-hidden">
        <!-- Sidebar -->
        <aside class="w-64 bg-slate-900 border-r border-slate-800 flex flex-col hidden md:flex h-full">
            <div class="p-4 flex items-center gap-3">
                <svg class="w-8 h-8 text-emerald-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                <span class="text-xl font-bold text-emerald-500 tracking-wider">CyberLog</span>
            </div>
            <nav class="flex-1 p-4 space-y-2">
                <a href="{% url 'dashboard:overview' %}" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 transition-colors">Dashboard</a>
                <a href="{% url 'logs:upload' %}" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 transition-colors">Upload Logs</a>
                <a href="{% url 'logs:list' %}" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 transition-colors">Log Explorer</a>
                <a href="{% url 'analytics:alerts' %}" class="flex items-center justify-between px-4 py-3 rounded-lg hover:bg-slate-800 transition-colors">
                    <span>Alerts</span>
                    {% if critical_alerts %}
                        <span class="bg-red-500 text-white text-xs px-2 py-1 rounded-full">{ { critical_alerts } }</span>
                    {% endif %}
                </a>
                <a href="{% url 'dashboard:reports' %}" class="flex items-center gap-3 px-4 py-3 rounded-lg hover:bg-slate-800 transition-colors">Reports</a>
            </nav>
            <div class="p-4 border-t border-slate-800">
                <div class="flex flex-col gap-2">
                    <span class="text-sm text-slate-400">Logged in as {{ user.username }}</span>
                    <a href="{% url 'accounts:profile' %}" class="text-sm hover:text-emerald-500">Profile</a>
                    <form action="{% url 'accounts:logout' %}" method="post">
                        {% csrf_token %}
                        <button type="submit" class="text-sm text-red-500 hover:text-red-400">Logout</button>
                    </form>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 flex flex-col h-full overflow-hidden">
            <header class="p-6">
                <h1 class="text-3xl font-semibold">{% block page_title %}{% endblock %}</h1>
            </header>
            
            <div class="flex-1 overflow-auto p-6 pt-0">
                {% if messages %}
                    <div class="mb-6 space-y-2">
                        {% for message in messages %}
                            <div class="p-4 rounded-lg bg-slate-800 border-l-4 {% if message.tags == 'error' %}border-red-500{% elif message.tags == 'success' %}border-emerald-500{% else %}border-blue-500{% endif %}">
                                {{ message }}
                            </div>
                        {% endfor %}
                    </div>
                {% endif %}
                
                {% block content %}{% endblock %}
            </div>
        </main>
    </div>
    {% block extra_js %}{% endblock %}
</body>
</html>"""

files["templates/components/pagination.html"] = """
{% if page_obj.has_other_pages %}
<div class="flex justify-center mt-6">
    <nav class="flex items-center gap-2">
        {% if page_obj.has_previous %}
            <a href="?page={{ page_obj.previous_page_number }}" class="px-3 py-1 rounded-md bg-slate-700 hover:bg-slate-600 text-sm">Prev</a>
        {% endif %}
        
        <span class="px-4 py-1 text-sm bg-emerald-600 rounded-md">Page {{ page_obj.number }} of {{ page_obj.paginator.num_pages }}</span>
        
        {% if page_obj.has_next %}
            <a href="?page={{ page_obj.next_page_number }}" class="px-3 py-1 rounded-md bg-slate-700 hover:bg-slate-600 text-sm">Next</a>
        {% endif %}
    </nav>
</div>
{% endif %}
"""

files["templates/accounts/login.html"] = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - CyberLog</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
    <div class="w-full max-w-md p-8 bg-slate-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl">
        <div class="flex justify-center mb-8">
            <h1 class="text-3xl font-bold text-emerald-500">CyberLog</h1>
        </div>
        <h2 class="text-2xl font-semibold mb-6 text-center">Sign In</h2>
        <form method="post" class="space-y-4">
            {% csrf_token %}
            {% for field in form %}
                <div>
                    {{ field.label_tag }}
                    <div class="mt-1">
                        {{ field }}
                    </div>
                    {% if field.errors %}
                        <p class="text-red-500 text-sm mt-1">{{ field.errors.0 }}</p>
                    {% endif %}
                </div>
            {% endfor %}
            <button type="submit" class="w-full py-3 bg-emerald-600 hover:bg-emerald-500 rounded-lg font-medium transition-colors">Sign In</button>
        </form>
        <p class="mt-6 text-center text-sm text-slate-400">Don't have an account? <a href="{% url 'accounts:register' %}" class="text-emerald-500 hover:underline">Register</a></p>
    </div>
</body>
</html>"""

files["templates/accounts/register.html"] = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - CyberLog</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
</head>
<body class="bg-slate-950 text-slate-100 font-sans min-h-screen flex items-center justify-center">
    <div class="w-full max-w-md p-8 bg-slate-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl">
        <div class="flex justify-center mb-8">
            <h1 class="text-3xl font-bold text-emerald-500">CyberLog</h1>
        </div>
        <h2 class="text-2xl font-semibold mb-6 text-center">Create Account</h2>
        <form method="post" class="space-y-4">
            {% csrf_token %}
            {% for field in form %}
                <div>
                    {{ field.label_tag }}
                    <div class="mt-1">
                        {{ field }}
                    </div>
                    {% if field.errors %}
                        <p class="text-red-500 text-sm mt-1">{{ field.errors.0 }}</p>
                    {% endif %}
                </div>
            {% endfor %}
            <button type="submit" class="w-full py-3 bg-emerald-600 hover:bg-emerald-500 rounded-lg font-medium transition-colors">Register</button>
        </form>
        <p class="mt-6 text-center text-sm text-slate-400">Already have an account? <a href="{% url 'accounts:login' %}" class="text-emerald-500 hover:underline">Sign in</a></p>
    </div>
</body>
</html>"""

files["templates/dashboard/overview.html"] = """{% extends 'base.html' %}
{% block title %}Dashboard | CyberLog{% endblock %}
{% block page_title %}Security Dashboard{% endblock %}

{% block content %}
<div class="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-slate-400 text-sm font-medium mb-2">Total Events</h3>
        <p class="text-3xl font-bold">{{ total_events }}</p>
    </div>
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-emerald-500/30">
        <h3 class="text-emerald-400 text-sm font-medium mb-2">Active Alerts</h3>
        <p class="text-3xl font-bold text-emerald-500">{{ total_alerts }}</p>
    </div>
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-slate-400 text-sm font-medium mb-2">Files Analyzed</h3>
        <p class="text-3xl font-bold">{{ total_files }}</p>
    </div>
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-red-500/50 relative overflow-hidden">
        <h3 class="text-red-400 text-sm font-medium mb-2">Critical Alerts</h3>
        <p class="text-3xl font-bold text-red-500">{{ critical_alerts }}</p>
        {% if critical_alerts > 0 %}
            <div class="absolute top-0 right-0 w-16 h-16 bg-red-500/20 rounded-bl-full animate-pulse"></div>
        {% endif %}
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
    <div class="lg:col-span-2 bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-lg font-semibold mb-4">Threat Timeline</h3>
        <div id="threat-timeline-chart" class="w-full h-[400px]"></div>
    </div>
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-lg font-semibold mb-4">Severity Distribution</h3>
        <div class="relative h-[300px] w-full flex items-center justify-center">
            <canvas id="severity-chart"></canvas>
        </div>
    </div>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-lg font-semibold mb-4">Top Attacking IPs</h3>
        <canvas id="attackers-chart" height="300"></canvas>
    </div>
    <div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
        <h3 class="text-lg font-semibold mb-4">Attack Origins</h3>
        <div id="geo-map" class="w-full h-[350px]"></div>
    </div>
</div>

<div class="bg-slate-800/70 backdrop-blur rounded-xl p-6 border border-slate-700/50">
    <div class="flex justify-between items-center mb-6">
        <h3 class="text-lg font-semibold">Recent Alerts</h3>
        <a href="{% url 'analytics:alerts' %}" class="text-emerald-500 hover:text-emerald-400 text-sm">View All &rarr;</a>
    </div>
    <div class="space-y-4">
        {% for alert in recent_alerts %}
            <div class="flex items-center gap-4 p-4 rounded-lg bg-slate-900/50 border border-slate-700/50">
                <div class="w-2 h-2 rounded-full bg-{{ alert.severity_color }}-500"></div>
                <div class="flex-1">
                    <h4 class="font-medium">{{ alert.title }}</h4>
                    <p class="text-sm text-slate-400">{{ alert.source_ip|default:"N/A" }} &bull; {{ alert.created_at|timesince }} ago</p>
                </div>
                <div>
                    <span class="px-2 py-1 text-xs rounded bg-slate-700">{{ alert.get_alert_type_display }}</span>
                </div>
            </div>
        {% empty %}
            <p class="text-slate-400 text-center py-4">No recent alerts found.</p>
        {% endfor %}
    </div>
</div>
{% endblock %}

{% block extra_js %}
<script src="{% static 'js/charts.js' %}"></script>
<script src="{% static 'js/dashboard.js' %}"></script>
{% endblock %}
"""

files["templates/logs/upload.html"] = """{% extends 'base.html' %}
{% block title %}Upload Logs | CyberLog{% endblock %}
{% block page_title %}Upload Log File{% endblock %}

{% block content %}
<div class="max-w-3xl mx-auto">
    <form method="post" enctype="multipart/form-data" id="upload-form" class="space-y-6">
        {% csrf_token %}
        
        <div id="drop-zone" class="border-2 border-dashed border-slate-600 rounded-xl bg-slate-800/30 p-12 text-center transition-all duration-200">
            <svg class="mx-auto h-16 w-16 text-slate-400 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
            </svg>
            <p class="text-xl font-medium mb-2">Drag and drop your log file here</p>
            <p class="text-sm text-slate-400 mb-6">Supported formats: .log, .txt, .csv</p>
            
            <div class="flex items-center justify-center gap-4 mb-4">
                <span class="h-px w-16 bg-slate-600"></span>
                <span class="text-slate-400 uppercase text-xs">or</span>
                <span class="h-px w-16 bg-slate-600"></span>
            </div>
            
            <button type="button" id="browse-btn" class="px-6 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition-colors">Browse Files</button>
            {{ form.file }}
            
            <div id="file-info" class="hidden mt-6 p-4 bg-slate-900 rounded-lg inline-flex items-center gap-4">
                <span id="filename" class="font-mono text-emerald-400"></span>
                <button type="button" id="remove-btn" class="text-red-400 hover:text-red-300">
                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
        </div>

        <div class="bg-slate-800/70 p-6 rounded-xl border border-slate-700/50">
            <label class="block mb-2 font-medium">Log Type</label>
            <p class="text-sm text-slate-400 mb-4">Auto-detect works for most standard formats. Select manually if auto-detect fails.</p>
            {{ form.log_type }}
        </div>
        
        <button type="submit" id="submit-btn" disabled class="w-full py-4 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed rounded-xl font-semibold text-lg transition-colors">
            Upload & Analyze
        </button>
    </form>
</div>
{% endblock %}

{% block extra_js %}
<script>
    document.addEventListener('DOMContentLoaded', () => {
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');
        const browseBtn = document.getElementById('browse-btn');
        const fileInfo = document.getElementById('file-info');
        const filenameSpan = document.getElementById('filename');
        const removeBtn = document.getElementById('remove-btn');
        const submitBtn = document.getElementById('submit-btn');
        const form = document.getElementById('upload-form');

        // Style the Django form select
        const select = document.querySelector('select[name="log_type"]');
        if (select) select.className = 'w-full bg-slate-900 border border-slate-700 rounded-lg px-4 py-3 focus:outline-none focus:border-emerald-500';

        browseBtn.addEventListener('click', () => fileInput.click());

        fileInput.addEventListener('change', handleFiles);
        removeBtn.addEventListener('click', clearFile);

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            dropZone.classList.add('border-emerald-500', 'bg-emerald-500/10');
        }

        function unhighlight(e) {
            dropZone.classList.remove('border-emerald-500', 'bg-emerald-500/10');
        }

        dropZone.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            fileInput.files = files;
            handleFiles();
        }

        function handleFiles() {
            if (fileInput.files.length > 0) {
                const file = fileInput.files[0];
                filenameSpan.textContent = file.name;
                fileInfo.classList.remove('hidden');
                submitBtn.disabled = false;
            }
        }

        function clearFile() {
            fileInput.value = '';
            fileInfo.classList.add('hidden');
            submitBtn.disabled = true;
        }
        
        form.addEventListener('submit', () => {
            if(!submitBtn.disabled) {
                submitBtn.innerHTML = '<span class="animate-pulse">Uploading and analyzing...</span>';
                submitBtn.disabled = true;
            }
        });
    });
</script>
{% endblock %}
"""

files["templates/analytics/alerts.html"] = """{% extends 'base.html' %}
{% block title %}Alerts | CyberLog{% endblock %}
{% block page_title %}Security Alerts{% endblock %}

{% block content %}
<!-- Stubbed for speed -->
<div class="text-xl">Alerts will be displayed here.</div>
{% endblock %}
"""

files["templates/logs/list.html"] = """{% extends 'base.html' %}
{% block title %}Log Explorer | CyberLog{% endblock %}
{% block page_title %}Log Explorer{% endblock %}

{% block content %}
<div class="mb-6 flex gap-4">
    <form method="get" class="flex-1 flex gap-4">
        <input type="text" name="q" value="{{ query|default:'' }}" placeholder="Search IP, description..." class="flex-1 bg-slate-800 border border-slate-700 rounded-lg px-4 py-2">
        <button type="submit" class="bg-slate-700 px-6 py-2 rounded-lg">Search</button>
    </form>
</div>
<div class="bg-slate-800/70 rounded-xl border border-slate-700/50 overflow-hidden">
    <table class="w-full text-left text-sm">
        <thead class="bg-slate-900/50 text-slate-400">
            <tr>
                <th class="p-4">Time</th>
                <th class="p-4">IP</th>
                <th class="p-4">Action</th>
                <th class="p-4">Severity</th>
                <th class="p-4">Desc</th>
            </tr>
        </thead>
        <tbody>
            {% for entry in entries %}
            <tr class="border-t border-slate-700/50 hover:bg-slate-700/30">
                <td class="p-4 whitespace-nowrap">{{ entry.timestamp|date:"Y-m-d H:i:s" }}</td>
                <td class="p-4 font-mono">{{ entry.source_ip|default:"-" }}</td>
                <td class="p-4">{{ entry.action }}</td>
                <td class="p-4"><span class="px-2 py-1 rounded text-xs bg-{{ entry.severity_color }}-500/20 text-{{ entry.severity_color }}-400">{{ entry.severity }}</span></td>
                <td class="p-4 truncate max-w-xs">{{ entry.description }}</td>
            </tr>
            {% empty %}
            <tr><td colspan="5" class="p-4 text-center text-slate-400">No logs found.</td></tr>
            {% endfor %}
        </tbody>
    </table>
</div>
{% include 'components/pagination.html' %}
{% endblock %}
"""

files["templates/logs/detail.html"] = """{% extends 'base.html' %}
{% block title %}Log Detail | CyberLog{% endblock %}
{% block page_title %}{{ log_file.filename }}{% endblock %}

{% block content %}
<div>Log file details...</div>
{% endblock %}
"""

files["templates/accounts/profile.html"] = """{% extends 'base.html' %}
{% block title %}Profile | CyberLog{% endblock %}
{% block page_title %}User Profile{% endblock %}

{% block content %}
<div>Profile details...</div>
{% endblock %}
"""

files["templates/dashboard/reports.html"] = """{% extends 'base.html' %}
{% block title %}Reports | CyberLog{% endblock %}
{% block page_title %}Reports{% endblock %}

{% block content %}
<div class="max-w-xl">
    <div class="bg-slate-800/70 p-6 rounded-xl border border-slate-700/50">
        <form action="{% url 'dashboard:report-download' %}" method="get" class="space-y-6">
            <div>
                <label class="block mb-2 font-medium">Format</label>
                <select name="format" class="w-full bg-slate-900 border border-slate-700 rounded-lg p-3">
                    <option value="pdf">PDF Document</option>
                    <option value="csv">CSV Spreadsheet</option>
                </select>
            </div>
            <button type="submit" class="w-full bg-emerald-600 py-3 rounded-lg font-medium">Download Report</button>
        </form>
    </div>
</div>
{% endblock %}
"""

files["static/js/charts.js"] = """
document.addEventListener('DOMContentLoaded', () => {
    // Basic chart initialization for demo
    fetch('/dashboard/api/severity-distribution/')
        .then(res => res.json())
        .then(data => {
            const ctx = document.getElementById('severity-chart');
            if (ctx) {
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: data.labels,
                        datasets: [{ data: data.data, backgroundColor: data.colors }]
                    },
                    options: { responsive: true, maintainAspectRatio: false }
                });
            }
        }).catch(e => console.error(e));
});
"""
files["static/js/dashboard.js"] = """
document.addEventListener('DOMContentLoaded', () => {
    // Plotly initialization stub
    console.log("Dashboard JS loaded");
});
"""

files["static/css/custom.css"] = """
@tailwind base;
@tailwind components;
@tailwind utilities;
"""

import sys
for path, content in files.items():
    full_path = os.path.join(base_dir, path)
    with open(full_path, "w", encoding="utf-8") as f:
        f.write(content)

print(f"Created {len(files)} frontend files successfully.")
