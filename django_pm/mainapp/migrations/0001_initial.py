# Generated by Django 3.1.7 on 2021-03-08 15:59

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='siteinfo',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(max_length=50, verbose_name='Название сайта')),
                ('login', models.TextField(max_length=50, verbose_name='Логин для авторизации')),
                ('password', models.TextField(max_length=50, verbose_name='Пароль для авторизации')),
            ],
        ),
    ]
