from django.shortcuts import render
from django.http import HttpResponse
from mainapp.models import siteinfo

# Create your views here.
def main_page(reguest):
    return render (reguest, 'main_page.html')

def add_info(reguest):
    B = siteinfo(name= reguest.POST.get("site", ""),
     login=reguest.POST.get("login", ""), 
     password = reguest.POST.get("password", ""))
    B.save()
    return render(reguest, 'main_page.html')

def open_add_site(reguest):
    return render (reguest, 'add_site.html')