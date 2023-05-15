from rest_framework import serializers
from .models import User_E
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import serializers
from django.contrib.auth.validators import validators
from rest_framework import serializers
# from django.conf.settings import MEDIA_ROOT, MEDIA_URL
from .models import Image
from django.conf import settings
from rest_framework import serializers
from django.core.exceptions import ValidationError
from django.core.validators import validate_image_file_extension
import os 
from .models import User_E

class ProfilePictureSerializer(serializers.Serializer):
    random_string = serializers.CharField(max_length=20)
    image = serializers.ImageField()

    def save(self):
        random_string = self.validated_data['random_string']
        image = self.validated_data['image']
        
        
        try:
            user = User_E.objects.get(random_string=random_string)
        except User_E.DoesNotExist:
            raise serializers.ValidationError('Invalid random_string')
        
        
        try:
            validate_image_file_extension(image)
        except ValidationError:
            raise serializers.ValidationError('Invalid image format')
        
        
        filename = f'{random_string}.jpg'
        filepath = os.path.join(settings.MEDIA_ROOT, 'profile_pictures')
        with open(filepath, 'wb') as f:
            for chunk in image.chunks():
                f.write(chunk)
        
        
        user.pic_path = filepath
        user.save()
        
        return user





class ForgotPasswordSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=50)
    otp = serializers.CharField(max_length=5)
    new_password = serializers.CharField(max_length=255, validators=[validators.MinLengthValidator(8)])




class UserSerializer(serializers.ModelSerializer):
    otp = serializers.CharField(write_only=True)

    class Meta:
        model = User_E
        fields = ['phone_number', 'otp']


    







from django.core.exceptions import ValidationError

class UserUpdateSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=255, write_only=True, validators=[validators.MinLengthValidator(8)])
    name = serializers.CharField(max_length=255)

    class Meta:
        model = User_E
        fields = ('name', 'date_of_birth', 'about', 'password')

    def validate_name(self, value):
        if value.strip() == '':
            raise ValidationError('Name cannot be blank')
        return value

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.date_of_birth = validated_data.get('date_of_birth', instance.date_of_birth)
        instance.about = validated_data.get('about', instance.about)
        password = validated_data.get('password', None)
        if password and len(password) < 8:
            raise serializers.ValidationError('Password should be at least 8 characters long.')
        instance.password = password if password else instance.password
        instance.save()
        return instance










    

    


class UserUpdateSerializer_2(serializers.ModelSerializer):
    email = serializers.EmailField()
    address = serializers.CharField(max_length=255)
    city = serializers.CharField(max_length=255)

    class Meta:
        model = User_E
        fields = ('email', 'address', 'city')

    def update(self, instance, validated_data):
        instance.email = validated_data.get('email', instance.email)
        instance.address = validated_data.get('address', instance.address)
        instance.city = validated_data.get('city', instance.city)
        instance.save()
        return instance


class UserESerializer(serializers.ModelSerializer):
    class Meta:
        model = User_E
        fields = ('phone_number', 'password')



class CheckPhoneNumberSerializer(serializers.ModelSerializer):
    class Meta:
        model = User_E
        fields = ('phone_number',)




class UserLoginSerializer(serializers.Serializer):
    phone_number = serializers.CharField(max_length=50)
    password = serializers.CharField(max_length=255)


