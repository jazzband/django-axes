from django.contrib import admin
from axes.models import AccessAttempt

class AccessAttemptAdmin(admin.ModelAdmin):
    list_display = ('attempt_time', 'ip_address', 'user_agent', 'path_info', 'status')
    list_filter = ['attempt_time', 'path_info', 'status']
    search_fields = ['ip_address', 'user_agent', 'path_info','user__username']
    date_hierarchy = 'attempt_time'
    fieldsets = (
        (None, {
            'fields': ('path_info', 'status')
        }),
        ('Form Data', {
            'fields': ('get_data', 'post_data')
        }),
        ('Meta Data', {
            'fields': ('user_agent', 'ip_address', 'http_accept')
        })
    )

admin.site.register(AccessAttempt, AccessAttemptAdmin)
