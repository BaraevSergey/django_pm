from django.shortcuts import render
from django.shortcuts import redirect
from django.http import HttpResponse
from mainapp.models import SiteInfo
from mainapp.models import LogInfo
from .forms import InputForm
from .forms import LoginForm
from .forms import RegisterForm
import hashlib #для хэширования
import logging #для логирования
from cryptography.fernet import Fernet #для шифрования
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# Create your views here.


def authority(request): #проверка авторизации
    if request.POST: #если пост запрос
        if 'login_button' in request.POST: # если нажата кнопка "Войти"
            
            #получаем данные из формы
            log_form = request.POST.get("login", "")
            pass_form = request.POST.get("password", "")
            hash_pass = hash_plus_salt(pass_form, log_form) #вызов функции хэширования, которая возвращает строку
            
            #получаем из бд данные, введённые в форму
            query_list_login = LogInfo.objects.all().filter(login = log_form)
            query_passwords = LogInfo.objects.all().filter(password = hash_pass)

            #создание ключа по паре логин пароль для шифрования
            key = get_cipher_key(log_form, pass_form).decode()
            pass_key = hashlib.sha512((log_form+pass_form).encode('utf-8')).hexdigest()

            if len(query_list_login) != 0 and query_passwords.exists(): # проверяем есть ли такой логин
                success_authority(request, hash_pass, log_form, pass_key, key)
                return redirect(main_page) #если пара логин-пароль совпала, то идём на страницу с паролями
            else:
                    return redirect(login_page) #если пароль не верный, то обновим логин пейдж
        elif 'register_button' in request.POST: #если кнопка регистрации то редиректнем на страницу регистрации
            return redirect(register_page)

def add_info(request):#добавление сайта со страницы добавления
    if request.method == "POST":
        form = InputForm()
        if form.is_valid:
            name_form = request.POST.get("name", "")
            login_form = request.POST.get("login", "") 
            pass_form = request.POST.get("password", "")
            
            ciph_pass = cipher_password(request, pass_form)

            B = SiteInfo(
                key_login = request.session['user_key'],
                name = name_form,
                login=login_form, 
                password = ciph_pass
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

    hash_pass = hash_plus_salt(pass_form, login_form) #вызов функции хэширования, которая возвращает строку
    
    query_list_login = LogInfo.objects.all().filter(login = login_form) #проверяем есть ли такой логин в регистрации

    #создание ключа по паре логин пароль для шифрования
    key = get_cipher_key(login_form, pass_form).decode()
    pass_key = hashlib.sha512((confirm_pass_form+login_form).encode('utf-8')).hexdigest() #для принадлежности пользователя

    if len(query_list_login) == 0:  
        if confirm_pass_form == pass_form:
            B = LogInfo(login = login_form,
                password = hash_pass)
            B.save()
            success_authority(request, hash_pass, login_form, pass_key , key)
            return redirect(main_page)
        else:
            return redirect(register_page)
            #пока так, тут надо сказать юзеру что его пара логин пароль некорректны и надо чтобы они были равны
    else:
        return redirect(register_page)
        #алерт о логине существующем

def open_add_site(request):
    form = InputForm()
    if (check_value_session(request)):
            clear_session(request)
    return render (
        request, 
        'add_site.html', 
        {
            'form': form,
            "user_key": request.session['user_key'], 
            "login":request.session['Login'], 
            "auth" : request.session['auth'],
            "pass_key" : request.session['pass_key']
        }
    )

def login_page(request):
    form = LoginForm()
    return render(request, 'login_page.html', {'form' : form})

def register_page(request):
    form = RegisterForm()
    return render(request, 'register_page.html', {'form' : form})

def main_page(request): #отрисовка мейна 
    
    if (check_value_session(request)):
        clear_session(request)

    all_sites = SiteInfo.objects.all().filter(key_login = request.session['user_key'])
    if request.session['key_for_cipher'] !=None: #тут почему то была трабла с None у этого ключа, поставил костыль
        Fer_Inst = Fernet(request.session['key_for_cipher'].encode())
        for a in all_sites:
            a.password = decipher_password(Fer_Inst, a)
       

    return render(
                request, 
                'main_page.html', 
                {
                    "all_sites": zip(all_sites, range(0, len(all_sites))), 
                    "user_key": request.session['user_key'], 
                    "login":request.session['Login'], 
                    "auth" : request.session['auth'],
                    "pass_key" : request.session['pass_key']
                }
            )

def exit(request):
    clear_session(request)
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


def hash_plus_salt(message, salt):#хэширование пароля + соль
    hash = hashlib.sha512(message.encode('utf-8')).hexdigest()
    hash_plus_salt = hashlib.sha512((hash+salt).encode('utf-8')).hexdigest() #соль в виде пароля
    return hash_plus_salt

def get_cipher_key(message1, message2):#создание ключа по паре логин пароль для шифрования
    my_key = (message1+message2).encode()
    salt = b'salt' # соль
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(my_key))
    return key

def clear_session(request): #очистка сессии
    request.session['user_key'] = None 
    request.session['Login'] = None 
    request.session['auth'] = False 
    request.session['pass_key'] = None 
    request.session['key_for_cipher'] = None 
    return None

def check_value_session(request): #проверка все ли значения сессии существуют(ошибка падает)
    if ('user_key' not in request.session or
        'Login' not in request.session or
        'auth' not in request.session or
        'pass_key' not in request.session or 
        'key_for_cipher' not in request.session):
        return True
    else:
        return False 

def cipher_password(request, password): # шифрование добавляемого пароля
    f = Fernet(request.session['key_for_cipher'].encode())
    cipher_password = f.encrypt(password.encode()).decode()
    return cipher_password

def decipher_password(Fer_Inst, site_row): #дешифровка одного пароля
    pass_bytes = (site_row.password).encode()
    dec_password = str(Fer_Inst.decrypt(pass_bytes))
    logging.debug(dec_password)
    dec_password = dec_password[2:len(dec_password)-1]
    logging.debug(dec_password)
    return dec_password

def success_authority(request, user_key, login, pass_key, key_for_cipher): #установка ключей в сессию
    request.session['user_key'] = user_key
    request.session['Login'] = login #для авторизации храним логин для отображения
    request.session['auth'] = True # указываем что прошла авторизация 
    request.session['pass_key'] = pass_key
    request.session['key_for_cipher'] = key_for_cipher#ключ для шифрования паролей
    return None
