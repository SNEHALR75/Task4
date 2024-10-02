from django.urls import path
from account.api import *


urlpatterns = [
	path('signin/',SignInView.as_view() ),
	path('signup/',SignUpView.as_view() ),
	path('user/info/',UserInfoView.as_view()),
	path('logout/',LogoutView.as_view() ),
	path('refresh/',CookieTokenRefreshView.as_view()),
    
	path('account/activate/<token>/',AccountActivationView.as_view()),
    path('account/reactivate/',AccountReActivationMailView.as_view()),
    path('account/deactivate/',AccountDeactivationView.as_view()),
	path('account/delete/',AccountDeleteView.as_view()),
    path('account/forgotpw/',ForgotPwMailView.as_view()),
	path('account/resetpw/<token>/',ResetPasswordView.as_view()),


    
]