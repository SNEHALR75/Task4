from rest_framework_simplejwt.authentication import JWTAuthentication
from django.conf import settings
from rest_framework import authentication, exceptions
from rest_framework.authentication import CSRFCheck

def enforce_csrf(request):
    check = CSRFCheck(request)
    reason = check.process_view(request, None, (), {})
    if reason:
      raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)



class CustomAuthentication(JWTAuthentication):
    def authenticate(self, request):

        header = self.get_header(request)

        raw_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE']) or None 

        print( header)
        print( raw_token )

        if header:
            raw_token = self.get_raw_token(header)

        if raw_token is None:
            return None
        
        validated_token = self.get_validated_token(raw_token)
        enforce_csrf(request)
        return self.get_user(validated_token), validated_token
        
