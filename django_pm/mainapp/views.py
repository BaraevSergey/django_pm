from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from mainapp.models import SiteInfo
from mainapp.models import LogInfo
from .forms import InputForm
from .forms import LoginForm
from .forms import RegisterForm
import hashlib
# Create your views here.

def authority(request): #проверка авторизации
    if request.POST: #если пост запрос
        if 'login_button' in request.POST: # если нажата кнопка "Войти"
            
            #получаем данные из формы
            log_form = request.POST.get("login", "")
            pass_form = request.POST.get("password", "")
            #Хэшируем и солим пароль
            hash_pass = hashlib.sha512((hashlib.sha512(pass_form.encode('utf-8'))).hexdigest().encode('utf-8')).hexdigest()
            #получаем из бд данные, введённые в форму
            query_list_login = LogInfo.objects.all().filter(login = log_form)
            query_passwords = LogInfo.objects.all().filter(password = hash_pass)
               
            if len(query_list_login) != 0 and query_passwords.exists(): # проверяем есть ли такой логин
                request.session['user_key'] = hash_pass
                request.session['Login'] = log_form #для авторизации храним логин для отображения
                request.session['auth'] = True # указываем что прошла авторизация 
                return redirect(main_page) #если пара логин-пароль совпала, то идём на страницу с паролями
            else:
                    return redirect(login_page) #если пароль не верный, то обновим логин пейдж
                    #тут ещё надо сообщение о том, что авторизация не прошла
        elif 'register_button' in request.POST: #если кнопка регистрации то редиректнем на страницу регистрации
            return redirect(register_page)



def add_info(request):#добавление сайта со страницы добавления
    if request.method == "POST":
        form = InputForm()
        if form.is_valid:
            name_form = request.POST.get("name", "")
            login_form = request.POST.get("login", "") 
            pass_form = request.POST.get("password", "")
            B = SiteInfo(
                key_login = request.session['user_key'],
                name = name_form,
                login=login_form, 
                password = pass_form
                )
            B.save()
        return redirect(main_page)
    else: 
        form = InputForm()
        return redirect(open_add_site)
    



def registration(request): #регистрация 
    login_form = request.POST.get("login", "")
    pass_form = request.POST.get("password", "")
    confirm_pass_form = request.POST.get("confirm_pass", "")
    
    #хэширование пароля
    hash_object = hashlib.sha512(confirm_pass_form.encode('utf-8'))
    hex_dig = hash_object.hexdigest()
    hex_dig = hashlib.sha512((hex_dig+pass_form).encode('utf-8')) #соль в виде пароля
    hex_dig = hex_dig.hexdigest()
    
    query_list_login = LogInfo.objects.all().filter(login = login_form) #проверяем есть ли такой логин в регистрации
    if len(query_list_login) == 0:
        if confirm_pass_form == pass_form:
            B = LogInfo(login = login_form,
                password = hex_dig)
            B.save()
            request.session['user_key'] = hex_dig
            request.session['Login'] = login_form #для авторизации храним логин для отображения
            request.session['auth'] = True # указываем что прошла авторизация
            return redirect(main_page)
        else:
            return redirect(register_page)
            #пока так, тут надо сказать юзеру что его пара логин пароль некорректны и надо чтобы они были равны
    else:
        return redirect(register_page)
        #алерт о логине существующем



def open_add_site(request):
    form = InputForm()
    if ('user_key' not in request.session or
        'Login' not in request.session or
        'auth' not in request.session):
            request.session['user_key'] = None 
            request.session['Login'] = None 
            request.session['auth'] = False
    return render (
        request, 
        'add_site.html', 
        {
            'form': form,
            "user_key": request.session['user_key'], 
            "login":request.session['Login'], 
            "auth" : request.session['auth']
        }
    )

def login_page(request):
    form = LoginForm()
    return render(request, 'login_page.html', {'form' : form})

def register_page(request):
    form = RegisterForm()
    return render(request, 'register_page.html', {'form' : form})

def main_page(request): #отрисовка мейна 
    
    if ('user_key' not in request.session or
        'Login' not in request.session or
        'auth' not in request.session):
            request.session['user_key'] = None 
            request.session['Login'] = None 
            request.session['auth'] = False   
    all_sites = SiteInfo.objects.all()
    return render(
                request, 
                'main_page.html', 
                {
                    "all_sites": zip(all_sites, range(0, len(all_sites))), 
                    "user_key": request.session['user_key'], 
                    "login":request.session['Login'], 
                    "auth" : request.session['auth']
                }
            )

def exit(request):
    request.session['user_key'] = None #зачищаем при выходе
    request.session['Login'] = None #зачищаем при выходе
    request.session['auth'] = False #зачищаем при выходе
    return redirect(login_page)


####этот пока не написан и нафиг он нужен тут
def action_main(request):
    if request.method == "POST":
        if 'add_site' in request.POST: # если нажата кнопка "Войти"
            return redirect(open_add_site)
        elif 'delete' in request.POST:
            id = request.POST.get("id")
            SiteInfo.objects.get.delete(pk=id)
            return redirect(main_page)
        elif 'edit' in request.POST:
            return redirect(main_page)
        else:
            return redirect(main_page)
    else:
        return redirect(main_page)
