"""
Forms for log file upload.

Provides a ModelForm for uploading log files with automatic or manual
log type detection. The file input is styled to support a drag-and-drop
UI with accepted file extensions restricted to .log, .txt, and .csv.
"""

from django import forms
from apps.logs.models import LogFile


class LogUploadForm(forms.ModelForm):
    """
    Form for uploading log files for analysis.
    
    Fields:
        file: The log file to upload (accepts .log, .txt, .csv)
        log_type: The type of log (auto-detect by default)
    
    The file input is hidden and controlled via a custom drag-and-drop
    UI in the template. The log_type defaults to 'auto' for automatic
    detection based on file content.
    """

    class Meta:
        model = LogFile
        fields = ['file', 'log_type']
        widgets = {
            'log_type': forms.Select(attrs={'class': 'form-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['log_type'].initial = 'auto'
        self.fields['file'].widget.attrs.update({
            'accept': '.log,.txt,.csv',
            'class': 'hidden',
            'id': 'file-input',
        })
        self.fields['log_type'].help_text = (
            'Select "Auto Detect" to automatically identify the log format.'
        )

    def clean_file(self):
        """Validate the uploaded file size and extension."""
        uploaded_file = self.cleaned_data.get('file')
        if uploaded_file:
            # Limit file size to 100MB
            max_size = 100 * 1024 * 1024
            if uploaded_file.size > max_size:
                raise forms.ValidationError(
                    'File size exceeds the maximum limit of 100MB.'
                )
            # Validate file extension
            valid_extensions = ['.log', '.txt', '.csv']
            file_ext = '.' + uploaded_file.name.rsplit('.', 1)[-1].lower() if '.' in uploaded_file.name else ''
            if file_ext not in valid_extensions:
                raise forms.ValidationError(
                    f'Unsupported file type. Allowed: {", ".join(valid_extensions)}'
                )
        return uploaded_file
