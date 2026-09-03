from django.contrib import admin

from .models import LoginLog


@admin.register(LoginLog)
class LoginLogAdmin(admin.ModelAdmin):
    list_display = ("user", "ip_address", "created_at")
    list_filter = ("created_at",)
    search_fields = ("user__username", "ip_address")
