from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from mainapp.models import siteinfo
from .forms import InputForm
from .forms import LoginForm

# Create your views here.
def main_page(request):
    all_sites = siteinfo.objects.all()
    return render (request, 'main_page.html', {"all_sites": all_sites}  )

def add_info(request):
    if request.method == "POST":
        form = InputForm()
        if form.is_valid:
            B = siteinfo(name= request.POST.get("name", ""),
                login=request.POST.get("login", ""), 
                password = request.POST.get("password", ""))
            B.save()
        return redirect(main_page)
    else: 
        form = InputForm()
    return render(request, add_info, {'form': form})

def open_add_site(request):
    form = InputForm()
    return render (request, 'add_site.html', {'form': form})

def redirect_login(request):
    return redirect(login_page)

def login_page(request):
    form = LoginForm()
    return render(request, 'login_page.html', {'form' : form})

