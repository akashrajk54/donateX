import os
import logging

from django.contrib.auth.hashers import make_password
from django.db import transaction
from dotenv import load_dotenv

from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.viewsets import ModelViewSet
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken
from django.utils import timezone

from accounts_engine.utils import (success_true_response, success_false_response, check_otp, get_stripe_api_key)
from accounts_engine.models import (CustomUser, InvalidatedToken, UserDonation)
from accounts_engine.serializer import (CustomUserSerializer, VerifyAccountSerializer, UserDonationSerializer)

from accounts_engine.sms import send_otp
from accounts_engine.status_code import BAD_REQUEST, INTERNAL_SERVER_ERROR, UNAUTHORIZED, NOT_FOUND
from django.views.decorators.csrf import csrf_exempt
import stripe
from django.http import HttpResponse
from django.utils.timezone import make_aware
from django.db.models.functions import TruncMonth
from django.db.models import Sum

logger = logging.getLogger(__name__)
logger_info = logging.getLogger('info')
logger_error = logging.getLogger('error')
load_dotenv()


class CustomUserViewSet(ModelViewSet):
    authentication_classes = [JWTAuthentication]
    queryset = CustomUser.objects.filter(is_delete=False, is_admin=False).order_by('-created_date')
    serializer_class = CustomUserSerializer

    def get_serializer(self, *args, **kwargs):
        """
        Use a custom serializer that includes nested objects.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()

        if self.action == 'create' or self.action == 'update':
            # Use a custom serializer for update actions that includes nested objects
            serializer_class = CustomUserSerializer
        return serializer_class(*args, **kwargs)

    def get_permissions(self):
        if self.request.method == "PATCH" or self.request.method == "PUT" or self.request.method == "DELETE" or self.request.method == "GET":
            return [IsAuthenticated()]
        else:
            return [AllowAny()]

    def perform_destroy(self, instance):
        instance.is_delete = True
        instance.save()

    @transaction.atomic
    def create(self, request, *args, **kwargs):
        try:
            contact = request.data.get('contact')
            user_queryset = CustomUser.objects.filter(contact=contact)
            if not user_queryset.exists():
                request.data['password'] = "Dedust!23"
                serializer = self.get_serializer(data=request.data)
                try:
                    serializer.is_valid(raise_exception=True)
                except ValidationError as e:
                    error_detail = e.detail
                    for field_name, errors in error_detail.items():
                        for error in errors:
                            message = str(error)
                            logger_error.error(message)
                            return Response(success_false_response(message=message), status=e.status_code)

                self.perform_create(serializer)
                instance = serializer.instance

                # Perform modifications before accessing serializer.data
                domain = request.get_host()
                sms_details = send_otp(instance.contact, domain)
                if sms_details['success']:
                    instance.otp = sms_details['otp']
                    instance.otp_send_datetime = timezone.now()
                    instance.password = make_password(instance.password)
                    instance.save()

                    message = f'Successfully signup verification otp send'
                    logger_info.info(f'{message} Phone number: {instance.contact}')
                    headers = self.get_success_headers(
                        serializer.data)
                    return Response(success_true_response(message=message), headers=headers)

                else:
                    instance.delete()
                    message = 'Invalid phone number entered'
                    logger_error.error(message)
                    return Response(success_false_response(message=message), status=BAD_REQUEST)

            user = user_queryset.first()

            domain = request.get_host()
            sms_details = send_otp(user.contact, domain)
            user.otp = sms_details['otp']
            user.otp_send_datetime = timezone.now()
            user.save()
            message = f'Successfully login verification otp send'
            logger_info.info(f'{message} Phone number: {user.contact}')
            return Response(success_true_response(message=message))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['PUT', 'PATCH'])
    def update_user(self, request, *args, **kwargs):

        try:
            partial = kwargs.pop('partial', True)
            instance = request.user
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            try:
                serializer.is_valid(raise_exception=True)
            except ValidationError as e:
                error_detail = e.detail
                for field_name, errors in error_detail.items():
                    for error in errors:
                        message = str(error)
                        logger_error.error(message)
                        return Response(success_false_response(message=message))

            self.perform_update(serializer)

            return Response(success_true_response(message="Profile updated successfully"))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['GET'])
    def get_user_profile(self, request, *args, **kwargs):

        try:
            instance = request.user
            serializer = self.get_serializer(instance)
            data = serializer.data

            message = 'Successfully fetched profile data.'
            logger_info.info(f'Successfully fetched user: {instance.username}, profile data.')
            return Response(success_true_response(data=data, message=message))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)


class VerifyOTPViewSet(ModelViewSet):
    queryset = CustomUser.objects.all()
    serializer_class = VerifyAccountSerializer

    def create(self, request, *args, **kwargs):
        try:
            # To reduce api call, sending profile data along with the access token.

            data = request.data
            contact = data['contact']
            input_otp = data['otp']
            user_queryset = CustomUser.objects.filter(contact=contact)

            if not user_queryset:
                message = 'Sorry, the phone number is not linked to an account. Please verify and try again.'
                logger_info.info(message)
                return Response(success_false_response(message=message), status=BAD_REQUEST)

            user = user_queryset.first()

            check_otp_details = check_otp(user, input_otp)

            if check_otp_details['is_verification_failed']:
                message = check_otp_details['message']
                logger_info.info(message)
                return Response(success_false_response(message=message), status=BAD_REQUEST)

            if not user.is_active:
                user.is_active = True
                user.save()
                logger_info.info('Successfully account activated.')

            refresh_token = RefreshToken.for_user(user)
            phone_number = '+' + str(user.contact.country_code) + str(user.contact.national_number)
            profile_data = {'username': user.username, 'about': user.about, 'contact': phone_number}

            # Create a dictionary containing the relevant data for your response
            response_data = {
                'access_token': str(refresh_token.access_token),
                'profile': profile_data,
            }

            logger_info.info('Login successful')

            return Response(success_true_response(data=response_data))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)


class LogoutAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:

            auth_header = request.META.get('HTTP_AUTHORIZATION')
            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header
            InvalidatedToken.objects.create(token=token)

            message = 'Successfully logout.'
            response = Response(success_true_response(message=message))

            logger_info.info(message)
            return response

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)


class SendOtpAPI(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            user = request.user
            domain = request.get_host()
            sms_details = send_otp(user.contact, domain)
            user.otp = sms_details['otp']
            user.otp_send_datetime = timezone.now()
            user.save()
            message = f'Successfully otp send to your registered number: {sms_details["otp"]}'
            logger_info.info(f'{message} Phone number: {user.contact}')
            return Response(success_true_response(message=message))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)


class UserDonationViewSet(ModelViewSet):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    queryset = UserDonation.objects.all()
    serializer_class = UserDonationSerializer


    def create(self, request, *args, **kwargs):

        try:
            amount = request.data.get('amount')
            currency = request.data.get('currency')
            payment_mode = request.data.get('payment_mode')
            if amount is None or amount == '':
                message = 'Please enter amount to donate'
                logger_info.error(message)
                return success_false_response(message=message)
            user = request.user

            # Get stripe api key
            stripe.api_key = get_stripe_api_key()

            # Get Customer Stripe ID
            stripe_customer_id = CustomUser.objects.filter(id=user.id).first().stripe_customer_id
            if stripe_customer_id is None:
                phone_number = '+' + str(user.contact.country_code) + str(user.contact.national_number)
                customer = stripe.Customer.create(
                    phone=phone_number,
                )

                stripe.Customer.modify(
                    customer.id,
                    phone=phone_number
                )

                user.stripe_customer_id = customer.id
                user.save()
                stripe_customer_id = user.stripe_customer_id

            # Get Domain name
            domain_name = request.build_absolute_uri('/')

            # Get the success_url and cancel_url based on the stripe mode
            success_url = ''
            cancel_url = ''
            current_mode = os.getenv('CURRENT_MODE')
            if current_mode == 'live':
                success_url = domain_name + os.getenv('LIVE_STRIPE_SUCCESS_URL')
                cancel_url = domain_name + os.getenv('LIVE_STRIPE_CANCEL_URL')
            elif current_mode == 'test':
                success_url = domain_name + os.getenv('TEST_STRIPE_SUCCESS_URL')
                cancel_url = domain_name + os.getenv('TEST_STRIPE_CANCEL_URL')

                # Create a new Checkout Session for the order
                amount = int(amount)*100
                checkout_session = stripe.checkout.Session.create(
                    customer=stripe_customer_id,
                    payment_method_types=[payment_mode],
                    line_items=[
                        {
                            'price_data': {
                                'currency': currency,
                                'product_data': {
                                    'name': 'Donation',
                                },
                                'unit_amount': amount,
                            },
                            'quantity': 1,
                        },
                    ],
                    mode='payment',
                    success_url=success_url,
                    cancel_url=cancel_url,
                )

            data = {"checkout_url": checkout_session.url}
            logger_info.info(f'Successfully subscription checkout url created for user: +{user.contact.country_code}{user.contact.national_number}')

            return Response(success_true_response(data=data, message='Please pay to this stripe url.'))

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['GET'])
    def get_payment_history_monthly(self, request, *args, **kwargs):
        try:
            # Get the year parameter from the query string
            user = request.user
            selected_year = self.request.query_params.get('selected_year')

            if selected_year:
                try:
                    selected_year = int(selected_year)
                except ValueError:
                    message = 'Invalid year format'
                    logger_error.error(message)
                    return Response(success_false_response(message=message), status=BAD_REQUEST)

            # Calculate the start and end dates based on the selected year
            if selected_year:
                start_date = make_aware(timezone.datetime(selected_year, 1, 1))
                end_date = make_aware(timezone.datetime(selected_year, 12, 31))
            else:
                # If no year is provided, default to the last 12 months
                end_date = timezone.now()
                start_date = end_date - timezone.timedelta(days=365)

            revenue_statistics = UserDonation.objects.filter(
                user=user,
                created_date__gte=start_date,
                created_date__lte=end_date,
                payment_status='paid',
            ).annotate(
                revenue_month=TruncMonth('created_date')
            ).values(
                'revenue_month'
            ).annotate(
                total_revenue=Sum('amount_total')
            ).order_by('revenue_month')

            # Create a list with the revenue for each month
            total_revenue_list = [0] * 12

            for stat in revenue_statistics:
                month_index = stat['revenue_month'].month - 1
                total_revenue_list[month_index] = stat['total_revenue']

            highest_amount = max(total_revenue_list)

            total_donated_amount = UserDonation.objects.filter(
                user=user,
                created_date__gte=start_date,
                created_date__lte=end_date,
                payment_status='paid',
            ).aggregate(total_amount=Sum('amount_total'))['total_amount']

            message = 'Successfully fetched data'
            logger_info.info(message)
            data = {
                'selected_year_revenue': total_revenue_list,
                'highest_amount': highest_amount,
                'total_donated_amount': total_donated_amount,
            }

            logger_info.info(f'Donated amount fetched by user +{user.contact.country_code}{user.contact.national_number}')
            response = Response(success_true_response(message=message, data=data))
            return response

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            user = request.user
            donation_history = UserDonation.objects.filter(user=user, payment_status='paid').order_by('-created_date')

            serializer = UserDonationSerializer(donation_history, many=True, context={'request': request})

            message = 'successfully payment history fetched'
            logger_info.info(
                f'Payment history fetched by user +{user.contact.country_code}{user.contact.national_number}')
            response = Response(success_true_response(message=message, data=serializer.data))
            return response

        except Exception as e:
            message = str(e)
            logger_error.error(message)
            return Response(success_false_response(message='Internal server error'), status=INTERNAL_SERVER_ERROR)


@csrf_exempt
def stripe_webhook(request):
    event = None
    payload = request.body
    sig_header = request.headers['STRIPE_SIGNATURE']

    # Get stripe webhook secret key
    webhook_secret = ''
    current_mode = os.getenv('CURRENT_MODE')
    if current_mode == 'live':
        webhook_secret = os.getenv('LIVE_STRIPE_WEBHOOK_SECRET')
    elif current_mode == 'test':
        webhook_secret = os.getenv('TEST_STRIPE_WEBHOOK_SECRET')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
    except ValueError as e:
        logger_error.error(f"Webhook ValueError : {e}")
        raise e
    except stripe.error.SignatureVerificationError as e:
        logger_error.error(f"Webhook  SignatureVerificationError: {e}")
        raise e

    try:

        if event['type'] == 'checkout.session.completed':
            try:
                logger_info.info('New session completed, starting update into the db.')
                session = event['data']['object']
                payment_intent_id = session['payment_intent']
                checkout_session_id = session['id']
                amount_total = int(session['amount_total'])/100
                payment_status = session['payment_status']
                stripe_customer_id = session['customer']
                user = CustomUser.objects.filter(stripe_customer_id=stripe_customer_id).first()

                UserDonation.objects.create(
                    user=user,
                    payment_intent_id=payment_intent_id,
                    checkout_session_id=checkout_session_id,
                    customer_id=stripe_customer_id,
                    amount_total=amount_total,
                    payment_status=payment_status
                )

                logger_info.info(f"Amount {amount_total} is donated by user: +{user.contact.country_code}{user.contact.national_number}")

            except Exception as e:
                message = 'Payment not completed, please try again'
                logger_error.error(message + " error: " + str(e))
                return Response(success_false_response(message=message), status=BAD_REQUEST)

        else:
            print('Unhandled event type {}'.format(event['type']))

    except Exception as e:
        logger_error.error(f"Exception Webhook : {e}")
    return HttpResponse(status=200)

