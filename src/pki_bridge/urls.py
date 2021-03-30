from django.urls import path, include
from django.conf import settings
from django.contrib import admin
from pki_bridge import views


# TODO: append slash without 301 redirect
# https://stackoverflow.com/questions/1596552/django-urls-without-a-trailing-slash-do-not-redirect


from django.http import HttpResponse
from django.core.mail import send_mail
from django.conf import settings


def index(request):
    x = send_mail(
        'sdf',
        'sdf',
        settings.DEFAULT_FROM_EMAIL,
        [
            # 'jurgeon018@gmail.com',
            'andrey.mendela@leonteq.com',
            'menan@leonteq.com',
        ],
        fail_silently=False
    )
    print(x)
    print(type(x))
    return HttpResponse('s')


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
    path("createkeyandcsr/", views.createkeyandcsr, name='createkeyandcsr'),
    path("createkeyandsign/", views.createkeyandsign, name='createkeyandsign'),
    path("revokecert/<id>/", views.revokecert, name='revokecert'),
    path("addnote/<id>/", views.addnote, name='addnote'),
    path("trackurl/", views.trackurl, name='trackurl'),
]

urlpatterns = [
    path('', index),
    path('admin/', admin.site.urls),
    path('api/v1/', include(api_urls)),
]

if settings.DEBUG:
    from django.conf.urls.static import static
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

