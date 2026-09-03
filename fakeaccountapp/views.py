from django.conf import settings
from django.contrib.admin.views.decorators import staff_member_required
from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import redirect, render

from .backup import decrypt_secure_backup
from .forms import RegistrationForm
from .models import LoginLog
from .signals import get_client_ip


def register(request):
    if request.method == "POST":
        form = RegistrationForm(request.POST)

        if form.is_valid():
            user = form.save(commit=False)
            user.set_password(form.cleaned_data["password"])
            user.save()

            ip = get_client_ip(request)
            if ip:
                LoginLog.objects.create(user=user, ip_address=ip)

            return redirect("login")
    else:
        form = RegistrationForm()

    return render(request, "register.html", {"form": form})


@staff_member_required
def download_decrypted_backup(request):
    backup_data = decrypt_secure_backup()
    response = HttpResponse(backup_data, content_type="application/json")
    response["Content-Disposition"] = 'attachment; filename="backup.json"'
    return response


def logout_view(request):
    logout(request)
    return redirect(settings.LOGOUT_REDIRECT_URL)
