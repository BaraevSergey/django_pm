from django.db import models

class SiteInfo (models.Model):
    ket_login = models.TextField(max_length=50, verbose_name="Принадлежность к аккаунту")
    name = models.TextField(max_length=50, verbose_name="Название сайта")
    login = models.TextField(max_length=50, verbose_name="Логин для авторизации")
    password = models.TextField(max_length=50, verbose_name="Пароль для авторизации")

class LogInfo(models.Model):
    login = models.TextField(max_length=50, verbose_name="Логин для авторизации")
    password = models.TextField(max_length=50, verbose_name="Пароль для авторизации")