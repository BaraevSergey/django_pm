from django import forms

class InputForm(forms.Form):
    name = forms.CharField(required=False, label="Название сайта")
    login = forms.CharField(required=False, label="Логин для авторизации")
    password = forms.CharField(required=False,  label="Пароль", min_length=5, widget=forms.PasswordInput())

class LoginForm(forms.Form):
    login = forms.CharField(required=False, label="Логин")
    password = forms.CharField(required=False, label="Пароль", min_length=5, widget=forms.PasswordInput())

class RegisterForm(forms.Form):
    login = forms.CharField(required=False, label="Логин")
    password = forms.CharField(required=False, label="Пароль", min_length=5, widget=forms.PasswordInput())
    confirm_pass = forms.CharField(required=False, label="Подтвердите пароль", min_length=5, widget=forms.PasswordInput())


class EditForm(forms.Form):
    site = forms.CharField(required=False, label = "Название сайта")
    login = forms.CharField(required=False, label = "Логин для авторизации")
    password = forms.CharField(required=False, label = "Пароль")