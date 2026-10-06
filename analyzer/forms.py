from django import forms

from .models import TestProject


class ProjectForm(forms.ModelForm):
    class Meta:
        model = TestProject
        fields = ['name', 'target_url', 'description', 'allowed_hosts']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
            'allowed_hosts': forms.Textarea(attrs={'rows': 3}),
        }


class NmapImportForm(forms.Form):
    nmap_file = forms.FileField(label='Kết quả Nmap XML',
                                widget=forms.ClearableFileInput(attrs={'accept': '.xml'}))
