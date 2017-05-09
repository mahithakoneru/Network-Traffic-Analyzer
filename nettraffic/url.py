from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$',views.index, name='index'),
    url(r'^findAllIPs/',views.findAllIPs),
    url(r'^findBLAccessingIPs/',views.findBLAccessingIPs),
    url(r'^findDownloads/',views.findDownloads),
]