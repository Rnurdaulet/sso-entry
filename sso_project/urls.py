from django.contrib import admin
from django.urls import path, include
from authprovider import views

urlpatterns = [
    path('.well-known/openid-configuration', views.well_known),
    path('authorize', views.authorize,name="authorize"),
    path('token', views.token),
    path('userinfo', views.userinfo),
    path('jwks', views.jwks),
    path("login/", views.login_view, name="login"),
    path("set-password/", views.set_password_view, name="set_password"),
]
from authprovider.api_views import ECPLoginView, PasswordLoginView, ChangePasswordView

urlpatterns += [
    path('api/login/ecp', ECPLoginView.as_view(), name="login_ecp"),
    path('api/login/password', PasswordLoginView.as_view(),  name="login_password"),
    path('api/password/change', ChangePasswordView.as_view()),
]

