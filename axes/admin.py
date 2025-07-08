from django.contrib import admin
from django.http import HttpRequest
from django.utils.translation import gettext_lazy as _

from axes.conf import settings
from axes.models import AccessAttempt, AccessLog, AccessFailureLog
from axes.handlers.database import AxesDatabaseHandler


class IsLockedOutFilter(admin.SimpleListFilter):
    title = _("Locked Out")
    parameter_name = "locked_out"

    def lookups(self, request, model_admin):
        return (
            ("yes", _("Yes")),
            ("no", _("No")),
        )

    def queryset(self, request, queryset):
        if self.value() == "yes":
            return queryset.filter(failures_since_start__gte=settings.AXES_FAILURE_LIMIT)
        elif self.value() == "no":
            return queryset.filter(failures_since_start__lt=settings.AXES_FAILURE_LIMIT)
        return queryset


class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = [
        "attempt_time",
        "ip_address",
        "user_agent",
        "username",
        "path_info",
        "failures_since_start",
    ]
    
    if settings.AXES_USE_ATTEMPT_EXPIRATION:
        list_display.append('expiration')

    list_filter = ["attempt_time", "path_info"]

    if isinstance(settings.AXES_FAILURE_LIMIT, int) and settings.AXES_FAILURE_LIMIT > 0:
        # This will only add the status field if AXES_FAILURE_LIMIT is set to a positive integer
        # Because callable failure limit requires scope of request object
        list_display.append("status")
        list_filter.append(IsLockedOutFilter)

    search_fields = ["ip_address", "username", "user_agent", "path_info"]

    date_hierarchy = "attempt_time"

    fieldsets = (
        (None, {"fields": ("username", "path_info", "failures_since_start", "expiration")}),
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
        "expiration",
    ]

    actions = ['cleanup_expired_attempts']

    @admin.action(description=_('Clean up expired attempts'))
    def cleanup_expired_attempts(self, request, queryset):
        count = self.handler.clean_expired_user_attempts(request=request)
        self.message_user(request, _(f"Cleaned up {count} expired access attempts."))

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.handler = AxesDatabaseHandler()

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    def expiration(self, obj: AccessAttempt):
        return obj.expiration.expires_at if hasattr(obj, "expiration") else _("Not set")
    
    def status(self, obj: AccessAttempt):
        return f"{settings.AXES_FAILURE_LIMIT - obj.failures_since_start} "+_("Attempt Remaining") if \
            obj.failures_since_start < settings.AXES_FAILURE_LIMIT else _("Locked Out")

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
