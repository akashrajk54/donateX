from rest_framework import serializers
from rest_framework.serializers import ModelSerializer, SerializerMethodField
from django.utils.html import strip_tags


from accounts_engine.utils import remove_special_char, has_country_code

from accounts_engine.models import CustomUser


class CustomUserSerializer(ModelSerializer):

    def validate(self, attrs):
        data = self.context.get('request').data

        if self.context.get('request').method == 'POST':
            contact = data.get('contact')

            if not has_country_code(contact):
                message = "Phone number does not have a country code."
                raise serializers.ValidationError(message)

        elif self.context.get('request').method == 'PUT' or self.context.get('request').method == 'PATCH':

            if attrs.get('username') is None or attrs.get('username') == '':
                message = "Username is must."
                raise serializers.ValidationError(message)

            if attrs.get('username'):
                attrs['username'] = remove_special_char(strip_tags(attrs['username'])).strip()
            return attrs

        return attrs

    class Meta:
        model = CustomUser
        fields = "__all__"

    def get_fields(self):
        fields = super().get_fields()
        request_method = self.context.get('request').method

        if request_method == 'GET':
            # Include only specific fields during GET request
            allowed_fields = ('id', 'username', 'about', 'contact', 'created_date')
            fields = {field: fields[field] for field in allowed_fields}

        return fields


class VerifyAccountSerializer(serializers.Serializer):
    otp = serializers.CharField()
