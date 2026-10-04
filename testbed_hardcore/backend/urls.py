"""URL configuration for hardcore testbed."""

from django.urls import path, include
from backend.views import urlpatterns as api_urls

urlpatterns = [
    path("", include(api_urls)),
]
