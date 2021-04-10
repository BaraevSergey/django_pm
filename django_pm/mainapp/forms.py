from django import forms

class InputForm(forms.Form):
    name = forms.CharField(label="Ваш сайт")
    login = forms.CharField(label="Ваш логин")
    password = forms.CharField(label="Ваш пароль", min_length=5, widget=forms.PasswordInput())

class LoginForm(forms.Form):
    login = forms.CharField(label="Введите логин")
    password = forms.CharField(label="Введите пароль", min_length=5, widget=forms.PasswordInput())

class RegisterForm(forms.Form):
    login = forms.CharField(label="Введите логин")
    password = forms.CharField(label="Введите пароль", min_length=5, widget=forms.PasswordInput())
    confirm_pass = forms.CharField(label="Подтвердите пароль", min_length=5, widget=forms.PasswordInput())


class EditForm(forms.Form):
    site = forms.CharField(label = "Название сайта")
    login = forms.CharField(label = "Ваш логин")
    password = forms.CharField(label = "Ваш пароль")