"""fundooNotes URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.conf.urls import url
from fundooapp import views
from django.urls import path


urlpatterns = [
    url('admin/', admin.site.urls),
    url('signup/', views.Signup.as_view()),
    path('activate/<token>', views.activate, name='activate'),
    url('login/', views.Login.as_view()),
    url('forgot_password/', views.ForgotPassword.as_view()),
    path('reset_password/<token>', views.ResetPassword.as_view(), name='reset_password'),
    url(r'note/create/', views.NoteView.as_view()),
    path(r'note/detail/<int:pk>', views.NoteUpdateView.as_view())
]
