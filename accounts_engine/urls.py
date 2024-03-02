from django.urls import path
from rest_framework.routers import DefaultRouter

from accounts_engine.views import (CustomUserViewSet, VerifyOTPViewSet, LogoutAPI, SendOtpAPI, UserDonationViewSet,
                                   stripe_webhook)

router = DefaultRouter()

router.register('user', CustomUserViewSet, basename='CustomUserViewSet')
router.register('verify-otp', VerifyOTPViewSet, basename='VerifyOTPViewSet')
router.register('amount-donate', UserDonationViewSet, basename='UserDonationViewSet')

urlpatterns = [
    path('logout/', LogoutAPI.as_view(), name='logout'),
    path('send-otp/', SendOtpAPI.as_view(), name='send-otp'),
    path('user/update-user-profile/', CustomUserViewSet.as_view({'put': 'update_user', 'patch': 'update_user'}), name='update-user-profile'),
    path('user/get-user-profile/', CustomUserViewSet.as_view({'get': 'get_user_profile'}), name='get-user-profile'),
    path("stripe-webhook/", stripe_webhook, name="stripe-webhook"),
    path('amount-donate/get-payment-history-monthly/', UserDonationViewSet.as_view({'get': 'get_payment_history_monthly'}), name='get-payment-history'),
    ] + router.urls
