from django.contrib import admin
from mainapp.models import SiteInfo
from mainapp.models import LogInfo
# Register your models here.

admin.site.register(SiteInfo)
admin.site.register(LogInfo)