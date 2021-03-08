from django.db import models

class siteinfo (models.Model):
    name = models.TextField(max_length=50, verbose_name="Название сайта")
    login = models.TextField(max_length=50, verbose_name="Логин для авторизации")
    password = models.TextField(max_length=50, verbose_name="Пароль для авторизации")