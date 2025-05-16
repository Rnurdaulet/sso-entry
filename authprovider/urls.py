from django.urls import path
from . import views_oidc, views_api
from .views_api import SetPasswordView, ForgotPasswordInitiateView, ForgotPasswordCompleteView
from .views_oidc import forgot_password_view, forgot_password_form_view

urlpatterns = [
    # OIDC Discovery & Auth endpoints
    path('.well-known/openid-configuration', views_oidc.well_known, name="well_known"),
    path('authorize', views_oidc.authorize, name="authorize"),
    path('token', views_oidc.token, name="token"),
    path('userinfo', views_oidc.userinfo, name="userinfo"),
    path('jwks', views_oidc.jwks, name="jwks"),

    # Login UI views
    path("login/", views_oidc.login_view, name="login"),
    path("set-password/", views_oidc.set_password_view, name="set_password"),
    path("forgot-password/", forgot_password_view, name="forgot_password"),
    path("forgot-password-form/", forgot_password_form_view, name="forgot_password_form"),

    # API endpoints (ECP / password login / password change)
    path("api/login/ecp", views_api.ECPLoginView.as_view(), name="login_ecp"),
    path("api/login/password", views_api.PasswordLoginView.as_view(), name="login_password"),
    path("api/password/set", SetPasswordView.as_view(), name="set_password_api"),
    path("api/password/forgot/initiate", ForgotPasswordInitiateView.as_view(), name="forgot_password_initiate"),
    path("api/password/forgot/complete", ForgotPasswordCompleteView.as_view(), name="forgot_password_complete"),
]
