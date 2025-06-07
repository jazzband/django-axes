from django.contrib import admin
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from axes.conf import settings
from axes.models import AccessAttempt, AccessLog, AccessFailureLog


class AccessAttemptAdmin(admin.ModelAdmin):
    if settings.AXES_USE_ATTEMPT_EXPIRATION:
        list_display = (
            "attempt_time",
            "expires_at",
            "ip_address",
            "user_agent",
            "username",
            "path_info",
            "failures_since_start",
        )
    else:
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
        (None, {"fields": ("username", "path_info", "failures_since_start", "expires_at")}),
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
        "expires_at",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def expires_at(self, obj: AccessAttempt):
        if hasattr(obj, "expiration") and obj.expiration.expires_at:
            return obj.expiration.expires_at #.strftime("%Y-%m-%d %H:%M:%S")
        return _("Not set")

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
        (None, {"fields": ("username", "path_info")}),
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

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


class AccessFailureLogAdmin(admin.ModelAdmin):
    list_display = (
        "attempt_time",
        "ip_address",
        "username",
        "user_agent",
        "path_info",
        "locked_out",
    )

    list_filter = ["attempt_time", "locked_out", "path_info"]

    search_fields = ["ip_address", "user_agent", "username", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("username", "path_info")}),
        (_("Meta Data"), {"fields": ("user_agent", "ip_address", "http_accept")}),
    )

    readonly_fields = [
        "user_agent",
        "ip_address",
        "username",
        "http_accept",
        "path_info",
        "attempt_time",
        "locked_out",
    ]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False


if settings.AXES_ENABLE_ADMIN:
    admin.site.register(AccessAttempt, AccessAttemptAdmin)
    admin.site.register(AccessLog, AccessLogAdmin)
    admin.site.register(AccessFailureLog, AccessFailureLogAdmin)
