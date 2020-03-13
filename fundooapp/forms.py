from django import forms


class ForgotPasswordForm(forms.Form):
    email = forms.CharField(label="Email", max_length=100)



class ResetPasswordForm(forms.Form):
    new_pswd = forms.CharField(label="New Password", max_length=50)
    confirm_pswd = forms.CharField(label="Confirm_Password", max_length=50)
