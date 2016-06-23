from django.contrib import admin

from axes.models import AccessLog
from axes.models import AccessAttempt


class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = (
        'attempt_time',
        'ip_address',
        'user_agent',
        'username',
        'path_info',
        'failures_since_start',
    )

    list_filter = [
        'attempt_time',
        'username',
        'path_info',
    ]

    search_fields = [
        'ip_address',
        'username',
        'user_agent',
        'path_info',
    ]

    date_hierarchy = 'attempt_time'

    fieldsets = (
        (None, {
            'fields': ('path_info', 'failures_since_start')
        }),
        ('Form Data', {
            'fields': ('get_data', 'post_data')
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )

admin.site.register(AccessAttempt, AccessAttemptAdmin)


class AccessLogAdmin(admin.ModelAdmin):
    list_display = (
        'attempt_time',
        'logout_time',
        'ip_address',
        'username',
        'user_agent',
        'path_info',
    )

    list_filter = [
        'attempt_time',
        'logout_time',
        'username',
        'path_info',
    ]

    search_fields = [
        'ip_address',
        'user_agent',
        'username',
        'path_info',
    ]

    date_hierarchy = 'attempt_time'

    fieldsets = (
        (None, {
            'fields': ('path_info',)
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )

admin.site.register(AccessLog, AccessLogAdmin)
