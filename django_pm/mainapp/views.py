from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from mainapp.models import SiteInfo
from mainapp.models import LogInfo
from .forms import InputForm
from .forms import LoginForm
from .forms import RegisterForm

# Create your views here.

def authority(request): #проверка авторизации
    if request.POST: #если пост запрос
        if 'login_button' in request.POST: # если нажата кнопка "Войти"
            
            #получаем данные из формы
            log_form = request.POST.get("login", "")
            pass_form = request.POST.get("password", "")

            #получаем из бд данные, введённые в форму
            query_list_login = LogInfo.objects.all().filter(login = log_form)
            query_passwords = LogInfo.objects.all().filter(password = pass_form)
            if len(query_list_login) != 0 : # проверяем есть ли такой логин
                if query_passwords.exists(): #проверяем совпал ли пароль
                    return redirect(main_page) #если пара логин-пароль совпала, то идём на страницу с паролями
                else:
                    return redirect(login_page) #если пароль не верный, то обновим логин пейдж
                    #тут ещё надо сообщение о том, что авторизация не прошла
            else:
                return redirect(login_page) #если логина нет, то бб
        elif 'register_button' in request.POST: #если кнопка регистрации то редиректнем на страницу регистрации
            return redirect(register_page)


def main_page(request): #отрисовка мейна 
    all_sites = SiteInfo.objects.all()
    return render (request, 'main_page.html', {"all_sites": all_sites}  )

def add_info(request):#добавление сайта со страницы добавления
    if request.method == "POST":
        form = InputForm()
        if form.is_valid:
            name_form = request.POST.get("name", "")
            login_form = request.POST.get("login", "") 
            pass_form = request.POST.get("password", "")
            B = SiteInfo(name = name_form,
                login=login_form, 
                password = pass_form)
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

def register_page(request):
    form = RegisterForm()
    return render(request, 'register_page.html', {'form' : form})


def registration(request): #регистрация 
    login_form = request.POST.get("login", "")
    pass_form = request.POST.get("password", "")
    confirm_pass_form = request.POST.get("confirm_pass", "")
    query_list_login = LogInfo.objects.all().filter(login = login_form) #проверяем есть ли такой логин в регистрации
    if len(query_list_login) == 0:
        if confirm_pass_form == pass_form:
            B = LogInfo(login = login_form,
                password = pass_form)
            B.save()
            return redirect(login_page) #редиректнуть потом на основную страницу, не логин page
        else:
            return redirect(register_page)
            pass #пока так, тут надо сказать юзеру что его пара логин пароль некорректны и надо чтобы они были равны
    else:
        return redirect(register_page)
        pass #алерт о логине существующем