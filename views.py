from django.shortcuts import render
from django.http import Http404
from rest_framework import generics, status
from rest_framework.response import Response
from django.contrib.auth import authenticate
from .models import User_E
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from .serializers import UserSerializer
from .serializers import CheckPhoneNumberSerializer
from .serializers import UserUpdateSerializer
from .serializers import UserUpdateSerializer_2
from .serializers import UserESerializer
from .serializers import ForgotPasswordSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.hashers import check_password
from rest_framework import exceptions
from django.shortcuts import get_object_or_404
from rest_framework import permissions
from rest_framework.response import Response
from rest_framework import status
from django.core.exceptions import ValidationError
from rest_framework import serializers, views, response
from rest_framework import views, response
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .serializers import ProfilePictureSerializer
from rest_framework.views import APIView
from rest_framework import status
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework import status
from .serializers import ForgotPasswordSerializer













################################################################################################################ ForGotPassword module API ################################################################


class ForgotPasswordView(APIView):
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            otp = serializer.validated_data['otp']
            new_password = serializer.validated_data['new_password']


            try:
                user = User_E.objects.get(phone_number=phone_number)
            except ObjectDoesNotExist:
                return JsonResponse({'error': 'Invalid phone number'}, status=status.HTTP_400_BAD_REQUEST)


            if otp != '12345':
                
                return JsonResponse({'error': 'Invalid OTP'}, status=status.HTTP_400_BAD_REQUEST)


            user.password = new_password

            user.save()
            payload = {
            # 'user_id': user.id,
            'id': user.phone_number,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            

        
            }
            token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

            return Response({'message': 'Password Changed successfully.', 'token': token}, status=status.HTTP_201_CREATED)

        





################################################################################################################ Login API Module ################################################################


class LoginAPI(APIView):
    serializer_class = UserESerializer
    def post(self, request):
        phone_number = request.data.get('phone_number')
        password = request.data.get('password')
        try:
            user = User_E.objects.get(phone_number=phone_number)
            if user.password == password:
                serializer = self.serializer_class(user)
                payload = {
            # 'user_id': user.id,
                'id': user.phone_number,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),}
                token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')
                return Response({'message': 'Login successfully.', 'token': token}, status=status.HTTP_201_CREATED)
            else:
                return response.Response({'detail': 'Invalid password.'}, status=400)
        except User_E.DoesNotExist:
            return response.Response({'detail': 'Wrong Phone number'}, status=400)
        
            


################################################################################################################ Profile Picture API Module ################################################################



class SaveProfilePictureView(APIView):
    def post(self, request, format=None):
        serializer = ProfilePictureSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'message': 'Profile picture saved successfully'})
        else:
            return Response(serializer.errors, status=400)



################################################################################################################ UserAuthenticationBackend API Module ################################################################


class UserAuthenticationBackend:
    def authenticate(self, request, phone_number=None, password=None):
        try:
            user = User_E.objects.get(phone_number=phone_number)
        except User_E.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid phone number or password.')

        if not user.check_password(password):
            raise exceptions.AuthenticationFailed('Invalid phone number or password.')

        return user



################################################################################################################ Sign-up API Module ################################################################


import jwt
import datetime
from django.conf import settings
from rest_framework.exceptions import AuthenticationFailed

class UserCreateView(generics.CreateAPIView):
    queryset = User_E.objects.all()
    serializer_class = UserSerializer

    def create(self, request):
        phone_number = request.data.get('phone_number')
        otp = request.data.get('otp')

        if User_E.objects.filter(phone_number=phone_number).exists():
            return Response({'message': 'User already exists with this phone number.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(phone_number) < 10 or len(phone_number) > 13:
            return Response({'error': 'INVALID NUMBER'}, status=status.HTTP_400_BAD_REQUEST)

        if otp != '12345':
            return Response({'message': 'Invalid OTP.'}, status=status.HTTP_400_BAD_REQUEST)

        # Create the user object
        user = User_E(
            phone_number=phone_number,
        )
        user.save()

        # Generate the JWT token
        payload = {
            # 'user_id': user.id,
            'id': user.phone_number,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=30),
            

        
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        return Response({'message': 'User created successfully.', 'token': token}, status=status.HTTP_201_CREATED)






################################################################################################################ Profile case 1 API Module ################################################################



# class UserUpdateView(generics.UpdateAPIView):
#     serializer_class = UserUpdateSerializer

#     def get_object(self):
#         random_string = self.kwargs.get('random_string')
#         obj = get_object_or_404(User_E, random_string=random_string)
#         return obj

#     def get_auth_token(self):
#         random_string = self.kwargs.get('random_string')
#         return f'Token {random_string}'

#     def put(self, request, *args, **kwargs):
#         user = self.get_object()
#         serializer = self.get_serializer(user, data=request.data, partial=True)
#         serializer.is_valid(raise_exception=True)
#         serializer.save()
#         return Response(serializer.data, status=status.HTTP_200_OK)
        


class UserUpdateView(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer
    def get_object(self):
    # Extract the JWT token from the Authorization header
        auth_header = self.request.headers.get('Authorization', '')
        if not auth_header:
            raise AuthenticationFailed('Authorization header missing')
        scheme, token = auth_header.split()
        if scheme.lower() != 'bearer':
            raise AuthenticationFailed('Invalid authentication scheme')
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user_id = payload.get('id')
            obj = get_object_or_404(User_E, phone_number=user_id)
            return obj
        except jwt.exceptions.DecodeError:
            raise AuthenticationFailed('Invalid token')

    


    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def perform_update(self, serializer):
        password = serializer.validated_data.get('password', None)
        if password and len(password) < 8:
            raise serializers.ValidationError('Password should be at least 8 characters long.')
        serializer.save()











################################################################################################################ Profile case 2 API Module ################################################################









class UserUpdateView_2(generics.UpdateAPIView):
    serializer_class = UserUpdateSerializer_2

    def get_object(self):
        random_string = self.request.headers.get('Token')
        obj = User_E.objects.filter(random_string=random_string).first()

        if obj is None:
            raise Http404('User not found')

        return obj

    def put(self, request, *args, **kwargs):
        try:
            user = self.get_object()
            serializer = self.get_serializer(user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        except Http404:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
    
################################################################################################################  Phone_number validation API Module ################################################################





class CheckPhoneNumberView(generics.GenericAPIView):
    serializer_class = CheckPhoneNumberSerializer

    def post(self, request):
        phone_number = request.data.get('phone_number')
        if not phone_number:
            return Response({'error': 'phone_number field is required.'}, status=status.HTTP_400_BAD_REQUEST)

        if len(phone_number) <= 10:
            return Response({'error': 'INVALID NUMBER'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User_E.objects.get(phone_number=phone_number)
            serialized_user = self.get_serializer(user)
            return Response({'message': 'This phone number is Already Exist.'}, status=status.HTTP_200_OK)
        except User_E.DoesNotExist:
            return Response({'message': 'This phone number is available for registration. \n OTP send SuccessFully'}, status=status.HTTP_200_OK)


