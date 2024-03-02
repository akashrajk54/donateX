import os
import re
import logging
from django.utils import timezone

logger = logging.getLogger(__name__)
logger_info = logging.getLogger('info')
logger_error = logging.getLogger('error')


def success_true_response(message=None, data=None, count=None):
    result = dict(success=True)
    result['message'] = message or ''
    result['data'] = data or {}
    if count is not None:
        result['count'] = count
    return result


def success_false_response(message=None, data=None):
    result = dict(success=False)
    result['message'] = message or ''
    result['data'] = data or {}

    return result


def remove_special_char(string):
    string = re.sub('[^A-Za-z0-9\s]+', '', string)
    return string


def has_country_code(phone_number):
    # Regular expression pattern to match country codes
    country_code_pattern = r'^\+\d+'

    # Use re.match to check if the pattern matches the beginning of the phone number
    match = re.match(country_code_pattern, phone_number)

    # If a match is found, it has a country code; otherwise, it doesn't
    return bool(match)


def check_otp(user, input_otp):

    # Check OTP before delete user
    otp_send_datetime = user.otp_send_datetime
    current_time = timezone.now()
    time_difference = current_time - otp_send_datetime

    is_verification_failed = False
    message = ''
    if time_difference > timezone.timedelta(minutes=int(os.getenv('MAX_TIME_LIMIT_TO_VERIFY_OTP'))):
        message = 'OTP is expired. Please generate a new one.'
        is_verification_failed = True

    elif int(input_otp) != int(user.otp):
        message = 'Invalid OTP entered. Please try again.'
        is_verification_failed = True

    verification_details = {'message': message, 'is_verification_failed': is_verification_failed}
    return verification_details


def get_stripe_api_key():
    current_mode = os.getenv('CURRENT_MODE')
    secret_api_key = ''
    if current_mode == 'live':
        secret_api_key = os.getenv('LIVE_STRIPE_SECRET_KEY_AYO')
    elif current_mode == 'test':
        secret_api_key = os.getenv('TEST_STRIPE_SECRET_KEY_AYO')
    return secret_api_key
