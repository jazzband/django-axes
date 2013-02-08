from django.contrib import admin
from axes.models import AccessAttempt, AccessLog


class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = ('username', 'attempt_time', 'ip_address', 'user_agent', 'path_info',
                    'failures_since_start', 'trusted')
    list_filter = ['attempt_time', 'ip_address', 'path_info']
    search_fields = ['ip_address', 'user_agent', 'username', 'path_info']
    date_hierarchy = 'attempt_time'
    fieldsets = (
        (None, {
            'fields': ('username', 'path_info', 'failures_since_start', 'attempt_time', 'trusted')
        }),
        ('Form Data', {
            'fields': ('get_data', 'post_data')
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )
    readonly_fields = AccessAttempt._meta.get_all_field_names()

admin.site.register(AccessAttempt, AccessAttemptAdmin)

class AccessLogAdmin(admin.ModelAdmin):
    list_display = ('attempt_time', 'username', 'logout_time', 'ip_address', 
        'user_agent', 'path_info')
    list_filter = ['attempt_time', 'logout_time', 'path_info']
    search_fields = ['ip_address', 'user_agent', 'username', 'path_info']
    date_hierarchy = 'attempt_time'
    fieldsets = (
        (None, {
            'fields': ('path_info',)
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )
    readonly_fields = AccessLog._meta.get_all_field_names()

admin.site.register(AccessLog, AccessLogAdmin)