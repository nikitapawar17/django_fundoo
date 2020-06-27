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
from django.views.generic import TemplateView
from fundooapp import views
from django.urls import path
from rest_framework_swagger.views import get_swagger_view

schema_view = get_swagger_view(title="FUNDOO")

urlpatterns = [
    url(r'^$', schema_view),
    url('admin/', admin.site.urls),
    url(r'user/register/', views.Register.as_view()),
    path(r'activate/<token>', views.activate, name='activate'),
    url(r'user/login/', views.Login.as_view()),
    url(r'user/forgot_password/', views.ForgotPassword.as_view()),
    path(r'user/reset_password/<token>', views.ResetPassword.as_view(), name='reset_password'),
    url(r'note/create/', views.NoteView.as_view()),
    path(r'note/detail/<int:pk>', views.NoteUpdateView.as_view()),
    path(r'note/delete/all/', views.NoteAllDelete.as_view()),

    path(r'note/trash/<int:pk>', views.TrashNote.as_view()),
    path(r'note/trash/', views.TrashNoteView.as_view()),

    path(r'note/pin/<int:pk>', views.PinNote.as_view()),
    path(r'note/pin/', views.PinNoteView.as_view()),

    path(r'note/unpin/<int:pk>', views.UnPinNote.as_view()),

    path(r'note/archive/<int:pk>', views.ArchiveNote.as_view()),
    path(r'note/archive', views.ArchiveNoteView.as_view()),

    path(r'note/add/<int:pk>/collaborator/', views.NoteCollaborator.as_view()),

    path(r'note/<int:pk>/remainder/', views.RemainderNote.as_view()),
    path(r'note/remainder', views.RemainderNoteView.as_view()),

    path(r'note/remove/remainder/<int:pk>', views.RemoveRemainderNote.as_view()),

    url(r'label/create/', views.LabelList.as_view()),
    path(r'label/detail/<int:pk>', views.LabelViewDetails.as_view()),

    path(r'label/add/<int:pk>', views.AddLabel.as_view())
]


