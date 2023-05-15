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


