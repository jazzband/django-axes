from django.conf.urls import patterns, include
from django.contrib import admin

urlpatterns = patterns('',
    (r'^admin/', include(admin.site.urls)),
)