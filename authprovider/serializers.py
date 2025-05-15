import re

from rest_framework import serializers


class PasswordLoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()
    client_id = serializers.CharField()
    redirect_uri = serializers.URLField()
    state = serializers.CharField()
    nonce = serializers.CharField()


class ECPLoginSerializer(serializers.Serializer):
    signed_data = serializers.CharField()
    nonce = serializers.CharField()
    client_id = serializers.CharField()
    redirect_uri = serializers.URLField()
    state = serializers.CharField()

class SetPasswordSerializer(serializers.Serializer):
    username = serializers.CharField()
    id_token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну заглавную букву (A–Z).")
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну строчную букву (a–z).")
        if not re.search(r"\d", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну цифру (0–9).")
        return value

class ForgotPasswordSerializer(serializers.Serializer):
    signed_data = serializers.CharField()
    id_token = serializers.CharField()
    new_password = serializers.CharField(min_length=8)

    def validate_new_password(self, value):
        if not re.search(r"[A-Z]", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну заглавную букву.")
        if not re.search(r"[a-z]", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну строчную букву.")
        if not re.search(r"\d", value):
            raise serializers.ValidationError("Пароль должен содержать хотя бы одну цифру.")
        return value