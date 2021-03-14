from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from mainapp.models import siteinfo
from .forms import InputForm

# Create your views here.
def main_page(request):
    all_sites = siteinfo.objects.all()
    return render (request, 'main_page.html', {"all_sites": all_sites}  )

def add_info(request):
    if request.method == "POST":
        form = InputForm(request.POST, use_required_attribute=False)
        B = siteinfo(name= request.POST.get("site", ""),
            login=request.POST.get("login", ""), 
            password = request.POST.get("password", ""))
        B.save()
        return redirect(main_page)
    else: 
        form = InputForm()
    return render(request, add_info, {'form': form})

def open_add_site(request):
    form = InputForm(use_required_attribute=False)
    return render (request, 'add_site.html', {'form': form})

def redirect_main(request):
    return redirect(main_page)