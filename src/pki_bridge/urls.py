from django.urls import path, include
from django.conf import settings
from django.contrib import admin
from pki_bridge import views


# TODO v2: append slash without redirect
api_urls = [
    path("listtemplates/", views.listtemplates, name='listtemplates'),
    path("pingca/", views.pingca, name='pingca'),
    path("signcert/", views.signcert, name='signcert'),
    path("getcert/<id>/", views.getcert, name='getcert'),
    path("getcacert/", views.getcacert, name='getcacert'),
    path("getintermediarycert/", views.getintermediarycert, name='getintermediarycert'),
    path("getcacertchain/", views.getcacertchain, name='getcacertchain'),
    path("listcommands/", views.listcommands, name='listcommands'),
    path("get_help/<command>/", views.get_help, name='get_help'),
    path("addnote/<id>/", views.addnote, name='addnote'),
    path("trackurl/", views.trackurl, name='trackurl'),
    # path("createkeyandcsr/", views.createkeyandcsr, name='createkeyandcsr'),
    # path("createkeyandsign/", views.createkeyandsign, name='createkeyandsign'),
    # path("revokecert/<id>/", views.revokecert, name='revokecert'),
]

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/v1/', include(api_urls)),
    path('test_mail/', views.test_mail, name='test_mail'),
]

if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

