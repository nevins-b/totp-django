from django.conf.urls import patterns, include, url

# Uncomment the next two lines to enable the admin:
from django.contrib import admin
admin.autodiscover()

urlpatterns = patterns('',
    # Examples:
    # url(r'^$', 'totp.views.home', name='home'),
    # url(r'^totp/', include('totp.foo.urls')),

    # Uncomment the admin/doc line below to enable admin documentation:
    # url(r'^admin/doc/', include('django.contrib.admindocs.urls')),

    # Uncomment the next line to enable the admin:
    url(r'^admin/', include(admin.site.urls)),
    url(r'^verify/user/', 'otp.views.verify_user'),
    url(r'^verify/token/', 'otp.views.verify_token'),
    url(r'^provision/user/', 'otp.views.provision_user'),
    url(r'^provision/secret/', 'otp.views.provision_secret'),
    url(r'^provision/scratch/', 'otp.views.provision_scratch'),
)
