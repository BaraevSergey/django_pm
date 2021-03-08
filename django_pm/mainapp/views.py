from django.shortcuts import render
from django.http import HttpResponse
from mainapp.models import siteinfo

# Create your views here.
def main_page(reguest):
    return render (reguest, 'main_page.html')

def add_info(reguest):
    B = siteinfo(name='test1', login='test2', password = 'test3')
    B.save()
    return render(reguest, 'main_page.html')