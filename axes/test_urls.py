from django.conf.urls import url
from django.contrib import admin

try:
    # django < 1.10
    from django.conf.urls import patterns
    from django.conf.urls import include

    urlpatterns = patterns(
        '',
        url(r'^admin/', include(admin.site.urls)),
    )
except ImportError:
    urlpatterns = [
        url(r'^admin/', admin.site.urls),
    ]
