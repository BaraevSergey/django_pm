from django import forms

class InputForm(forms.Form):
    name=forms.CharField(label="Ваш сайт", max_length=50)
    login=forms.CharField(label="Ваш логин", max_length=50)
    password=forms.CharField(label="Ваш пароль", min_length=8, max_length=50)
