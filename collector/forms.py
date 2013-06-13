from django import forms

class AddMalwareForm(forms.Form):
    tags = forms.CharField(max_length=255)
    url  = forms.CharField(max_length=1024, required=False)
    file = forms.FileField()

class FindMalwareForm(forms.Form):
    md5 = forms.CharField(max_length=32, required=False)
    sha1 = forms.CharField(max_length=40, required=False)
    sha256 = forms.CharField(max_length=64, required=False)
    ssdeep = forms.CharField(max_length=255, required=False)
    tag = forms.CharField(max_length=255, required=False)
    date = forms.DateTimeField(required=False)
