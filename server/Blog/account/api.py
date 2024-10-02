from rest_framework.response import Response
from rest_framework.generics import CreateAPIView
from rest_framework.views import APIView
from account.serializers import UserSerializer
from account.authenticate import CustomAuthentication
from django.middleware import csrf
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework_simplejwt import tokens as jwt_tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from datetime import datetime,timezone,timedelta
import jwt
from .utils import async_send_email
from rest_framework import viewsets

import logging
logger = logging.getLogger(__name__)

from django.contrib.auth import get_user_model
User = get_user_model()


class IsAdminUser(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = User.objects.all()
    authentication_classes = [CustomAuthentication]
    permission_classes = [IsAuthenticated,IsAdminUser]
    http_method_names =['get','delete']



class SignUpView(CreateAPIView):
    serializer_class = UserSerializer
    queryset = User.objects.all()

    def perform_create(self,serializer):
        user = serializer.save(is_active=False)

        jwt_payload = jwt.encode(
            {
                "exp":datetime.now(tz=timezone.utc) + timedelta(minutes=15),
                "user": user.id
            },"secret")
        print(jwt_payload)
        print( f'http://127.0.0.1:3000/account/activate/{jwt_payload}/' )

          #mail 
        async_send_email(
        subject = "Account Activation Mail",
             message = f"Your Account Activation Link : http://127.0.0.1:3000/account/activate/{jwt_payload}/",
                from_email = settings.EMAIL_HOST_USER,
            recipient_list = [ user.email ]
        )
        logger.info(f"New User created: {serializer.data['username']}")

class AccountActivationView(APIView):
    def post(self,request,token):
        try:
            jwt_payload = jwt.decode(token, "secret", algorithms=["HS256"])
            # print( jwt_payload )
        except jwt.ExpiredSignatureError:
            print( 'expired token' )
            return Response(data={"detail":'InvalidToken.'},status=400)
        except Exception as e:
            print( e )
            return Response(data={"detail":'InvalidToken.'},status=400)
        else:
            user = get_object_or_404(User, id=jwt_payload.get( 'user' ) )
            user.is_active = 1
            user.save()
        
            return Response(data={"detail":'Account activated.'},status=200)
        

class AccountReActivationMailView(APIView):
    def post(self,request):
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except User.DoesNotExist:
            return Response(data={"detail":"Incorrect un/pw."},status=400)
        
        if user.check_password( password ):
            
            jwt_payload = jwt.encode(
                {"exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15),
                "user": user.id }, "secret")
            print( jwt_payload )

            # mail
            async_send_email(
                subject = "Account Activation Mail",
                message = f"Your Reset Password Link : http://127.0.0.1:3000/account/activate/{jwt_payload}/",
                from_email = settings.EMAIL_HOST_USER,
                recipient_list = [ user.email ]
             )
            
            return Response(data={"detail":"Link sended.",
                    "link" : f'http://127.0.0.1:3000/account/activate/${jwt_payload}/'
                    },status=200
                )
        return Response(data={"detail":"Incorrect un/pw."},status=404)



def get_tokens_for_user(user):
    refresh = jwt_tokens.RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }

class SignInView(APIView):

    def post(self,request):
        response = Response()
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except:
            return Response(data={"detail":"Incorrect un/pw."},status=400)
        else:
            if user.check_password(password):
                if not user.is_active:
                    return Response(data={"detail":"Inactive Account."},status=400)

                tokens = get_tokens_for_user(user)
                response = Response(data=tokens)
                response.set_cookie(
                         key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                         value = tokens["access"],
                         expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                         secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                         httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                         samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                     )
                response.set_cookie(
                        key = settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'], 
                        value = tokens["refresh"],
                        expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                        secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                        httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                        samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                    )
                logger.info(f"User logged in: {user.username}")

            else:
                return Response(data={"detail":"Incorrect un/pw."},status=400)
            response["X-CSRFToken"] = csrf.get_token(request)
            return response
        

class LogoutView(APIView):

    def post(self,request):
        response = Response()
        try:
            refreshToken = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            token = jwt_tokens.RefreshToken(refreshToken)
            token.blacklist()
        except Exception as e:
            print(e)
            response = Response(data={"detail": "Invalid Token."},status=400)
        finally:
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
            response.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            response.delete_cookie("X-CSRFToken")
            response.delete_cookie("csrftoken")
            response["X-CSRFToken"]=None
        logger.info(f"User logged out: {request.user.username}")
        return response

class UserInfoView(APIView):
    permission_classes = [IsAuthenticated,]
    authentication_classes = [CustomAuthentication,]
    def get(self,request):
        serializer = UserSerializer(request.user)
        return Response( data=serializer.data, status=200 )



class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken("No valid token found in cookie 'refresh'.")


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        print( response.data )   
        try:
            response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
            response.set_cookie(
                            key = settings.SIMPLE_JWT['AUTH_COOKIE'], 
                            value = response.data["access"],
                            expires = settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                            secure = settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                            httponly = settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                            samesite = settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
                        )

        except Exception as e:
            print(e)

        return super().finalize_response(request, response, *args, **kwargs)
    

class AccountDeactivationView(APIView):
    permission_classes = [IsAuthenticated,]
    authentication_classes = [CustomAuthentication,]
    
    def post(self,request):
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except User.DoesNotExist:
            return Response(data={"detail":"Incorrect un/pw."},status=400)

        if user != request.user:
            return Response(status=400)
        
        if user.check_password( password ):
            user.is_active = 0
            user.save()
            return Response(data={"detail":"Account Deactivated."},status=200)
        return Response(data={"detail":"Incorrect un/pw."},status=404)


class AccountDeleteView(APIView):
    permission_classes = [IsAuthenticated,]
    authentication_classes = [CustomAuthentication,]
    def post(self,request):
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except User.DoesNotExist:
            return Response(data={"detail":"Incorrect un/pw."},status=400)

        if user != request.user:
            return Response(status=400)
        
        if user.check_password( password ):
            user.delete()
            return Response(data={"detail":"Account Deleted."},status=204)
        return Response(data={"detail":"Incorrect un/pw."},status=404)
    

class ForgotPwMailView(APIView):
    def post(self,request):
        try:
            email=request.data.get('email')
            user = User.objects.get( email=email )
        except User.DoesNotExist:
            return Response(status=404)
        jwt_payload = jwt.encode(
            {"exp": datetime.now(tz=timezone.utc) + timedelta(minutes=15),
            "user": user.id }, "secret")
        print( jwt_payload )

        # mail
        async_send_email(
             subject = "Account Activation Mail",
             message = f"Your Reset Password Link : http://127.0.0.1:3000/account/resetPw/{jwt_payload}/ ",
             from_email = settings.EMAIL_HOST_USER,
             recipient_list = [ user.email ]
         )

        return Response(data={"detail":"Link sended.",
            "link" : f'http://127.0.0.1:3000/${jwt_payload}'
            },

            status=200)



class ResetPasswordView(APIView):
    def post(self,request,token):
        try:
            username=request.data.get('username')
            password=request.data.get('password')
            user = User.objects.get( username=username )
        except User.DoesNotExist:
            return Response(data={"detail":"Incorrect un/pw."},status=400)
        else:
            try:
                jwt_payload = jwt.decode(token, "secret", algorithms=["HS256"])
                # print( jwt_payload )
            except jwt.ExpiredSignatureError:
                print( 'expired token' )
                return Response(data={"detail":'InvalidToken.'},status=400)
            except Exception as e:
                print( e )
                return Response(data={"detail":'InvalidToken.'},status=400)
            
            user.set_password(password)
            user.save()
            return Response(data={"detail":"Password Reset Successfully."},status=200)
        



