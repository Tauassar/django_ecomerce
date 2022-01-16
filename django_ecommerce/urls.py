from django.conf.urls import include
from django.urls import re_path

from contact.views import contact as contact_view
from main import views as main_views
from payments import views
from django.contrib import admin

admin.autodiscover()

urlpatterns = [
    re_path(r'^admin/', admin.site.urls),
    re_path(r'^$', main_views.index, name='home'),
    re_path(r'^pages/', include('django.contrib.flatpages.urls')),
    re_path(r'^contact/', contact_view, name='contact'),
    # user registration/authentication
    re_path(r'^sign_in$', views.sign_in, name='sign_in'),
    re_path(r'^sign_out$', views.sign_out, name='sign_out'),
    re_path(r'^register$', views.register, name='register'),
    re_path(r'^edit$', views.edit, name='edit'),
]
