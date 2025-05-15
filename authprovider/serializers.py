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
    new_password = serializers.CharField(min_length=6)
    id_token = serializers.CharField()