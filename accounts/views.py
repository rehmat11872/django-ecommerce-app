from base64 import urlsafe_b64encode
from email import message
import email
from xml.etree.ElementInclude import default_loader
from django.http import HttpResponse
from django.shortcuts import redirect, render
from .models import *
from accounts.models import Account
from .forms import RegistrationForm
from django.contrib import messages, auth
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
#User Activation
from django.contrib.sites.shortcuts import get_current_site  
from django.utils.encoding import force_bytes, force_text  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.template.loader import render_to_string  
from django.contrib.auth.tokens import default_token_generator
# from .tokens import account_activation_token  
from django.contrib.auth.models import User  
from django.core.mail import EmailMessage   
# Create your views here.
def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']
            username = email.split("@")[0]
            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, password=password, username=username)
            user.phone_number = phone_number
            user.save()

            # User Activation
            current_site = get_current_site(request)
            mail_subject = 'Please Active your Account'
            message = render_to_string('accounts/account_verification_email.html', {
               'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
               }
            )
            to_email = email
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()
            # messages.success(request, 'Thank you for Registration. We have sent verifiaction email to your email address. Please verify it.')
            return redirect('/accounts/login/?command=verification&email='+email)
    else:
        form = RegistrationForm()
    context = {
            'form': form,
        }
    return render(request, 'accounts/register.html', context)

def login(request):
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']
        print(email, password)

        user = auth.authenticate(request, email=email, password=password)
        print(user, 'login:::::::')
        if user is not None:
            auth.login(request, user) 
            messages.success(request, 'Login Successfully')
            return redirect('dashboard')
        else:
            messages.error(request, 'Invalid login Credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')


@login_required(login_url='login')
def logout(request):
    auth.logout(request)
    return redirect('login')

def activate(request, uidb64, token):
    try:  
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)  
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):  
        user = None  
    if user is not None and default_token_generator.check_token(user, token):  
        user.is_active = True  
        user.save()  
        messages.success(request, 'Congratulation! your account is Activated.')
        return redirect('login')
    else: 
        messages.error(request, 'Activation link is invalid!') 
        return redirect('register')

@login_required(login_url='login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')
    


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)

            current_site = get_current_site(request)
            mail_subject = 'Reset your password'
            message = render_to_string('accounts/reset_password_email.html', {
               'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
               }
            )
            to_email = email
            email = EmailMessage(mail_subject, message, to=[to_email])
            email.send()

            messages.success(request, 'Reset email has been sent to your email address')
            return redirect('login')

        else:
            messages.error(request, 'Account Does not exist!')  
            return redirect('forgotPassword')  
    return render(request, 'accounts/forgotPassword.html')    

def resetpassword_validate(request):
    return HttpResponse('ok')    