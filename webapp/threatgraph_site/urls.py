from django.contrib import admin
from django.urls import include, path
from django.views.generic.base import RedirectView

from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', RedirectView.as_view(url='admin/')),
    path('api/', include('catalog.api_urls')),
    path('stats/', views.stats),
    path('vulnerability/<str:cve_id>/', views.vulnerability),
]
