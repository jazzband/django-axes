from django.contrib import admin
from django.utils.translation import gettext_lazy as _

from axes.conf import settings
from axes.models import AccessAttempt, AccessLog


class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = (
        "attempt_time",
        "ip_address",
        "user_agent",
        "username",
        "path_info",
        "failures_since_start",
    )

    list_filter = ["attempt_time", "path_info"]

    search_fields = ["ip_address", "username", "user_agent", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("path_info", "failures_since_start")}),
        (_("Form Data"), {"fields": ("get_data", "post_data")}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "get_data",
        "post_data",
        "failures_since_start",
    ]

    def has_add_permission(self, request):
        return False


class AccessLogAdmin(admin.ModelAdmin):
    list_display = (
        "attempt_time",
        "logout_time",
        "ip_address",
        "username",
        "user_agent",
        "path_info",
    )

    list_filter = ["attempt_time", "logout_time", "path_info"]

    search_fields = ["ip_address", "user_agent", "username", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("path_info",)}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "logout_time",
    ]

    def has_add_permission(self, request):
        return False


if settings.AXES_ENABLE_ADMIN:
    admin.site.register(AccessAttempt, AccessAttemptAdmin)
    admin.site.register(AccessLog, AccessLogAdmin)
