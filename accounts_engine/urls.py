from django.urls import path
from rest_framework.routers import DefaultRouter

from accounts_engine.views import (CustomUserViewSet, VerifyOTPViewSet, LogoutAPI, SendOtpAPI)

router = DefaultRouter()

router.register('user', CustomUserViewSet, basename='CustomUserViewSet')
router.register('verify-otp', VerifyOTPViewSet, basename='VerifyOTPViewSet')


urlpatterns = [
    path('logout/', LogoutAPI.as_view(), name='logout'),
    path('send-otp/', SendOtpAPI.as_view(), name='send-otp'),
    path('user/update-user-profile/', CustomUserViewSet.as_view({'put': 'update_user', 'patch': 'update_user'}), name='update-user-profile'),
    path('user/get-user-profile/', CustomUserViewSet.as_view({'get': 'get_user_profile'}), name='get-user-profile'),
    path('user/get-all-users/', CustomUserViewSet.as_view({'get': 'get_all_users'}), name='get-all-users'),
    ] + router.urls

