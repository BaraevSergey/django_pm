from django.db import models

class SiteInfo (models.Model):
    key_login = models.TextField(max_length=50, verbose_name="Принадлежность к аккаунту", default="None") #не проводилась миграция, пришлось добавить дефолт ((
    name = models.TextField(max_length=50, verbose_name="Название сайта")
    login = models.TextField(max_length=50, verbose_name="Логин для авторизации")
    password = models.TextField(max_length=50, verbose_name="Пароль для авторизации")
    class Meta:
        verbose_name="Таблица со всеми сайтами"
class LogInfo(models.Model):
    login = models.TextField(max_length=50, verbose_name="Логин для авторизации")
    password = models.TextField(max_length=50, verbose_name="Пароль для авторизации")
    class Meta:
        verbose_name="Таблица всех зарегистрированных пользователей"