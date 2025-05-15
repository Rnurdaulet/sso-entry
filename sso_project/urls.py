from django.urls import path, include

urlpatterns = [
    path("", include("authprovider.urls")),  # 👈 все маршруты внутри
]
