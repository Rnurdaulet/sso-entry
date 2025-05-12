from django.contrib import admin
from django.urls import path, include
from authprovider import views

urlpatterns = [
    path('.well-known/openid-configuration', views.well_known),
    path('authorize', views.authorize),
    path('token', views.token),
    path('userinfo', views.userinfo),
    path('jwks', views.jwks)
]
from authprovider.api_views import ECPLoginView, PasswordLoginView, ChangePasswordView

urlpatterns += [
    path('api/login/ecp', ECPLoginView.as_view()),
    path('api/login/password', PasswordLoginView.as_view()),
    path('api/password/change', ChangePasswordView.as_view()),
]

