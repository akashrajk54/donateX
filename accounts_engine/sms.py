import os
import threading
import time

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client
from django.conf import settings
import random
import logging
from accounts_engine.models import CustomUser
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)
logger_info = logging.getLogger('info')
logger_error = logging.getLogger('error')


def check_status(client, message_sid, contact):
    time.sleep(30)
    message = client.messages(message_sid).fetch()
    logger_info.info(f'Last SMS Status For {contact} : {message.status}')
    user = CustomUser.objects.get(contact=contact)
    user.last_otp_status = message.status
    user.save()


def send_otp(contact, domain):
    try:
        otp = random.randint(1000, 9999)
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        body = f'Your DonateX verification code is: {otp}'
        phone_number = '+' + str(contact.country_code) + str(contact.national_number)
        message = client.messages.create(
            body=body,
            from_=os.getenv("TWILIO_PHONE_NUMBER"),
            to=phone_number,
            status_callback=f"http://{domain}/message-status/"
        )

        status_thread = threading.Thread(target=check_status, args=(client, message.sid, contact))
        status_thread.start()

        logger_info.info(f'verification otp: {otp}')
        logger_info.info('Successfully verification code sent.')
        data = {'success': True, 'otp': otp}
        return data

    except TwilioRestException as e:
        print(e)
        logger_error.error('Twilio Error: ' + str(e))
        data = {'success': False, 'otp': None}
        return data

    except Exception as e:
        logger_error.error('Invalid phone number entered' + str(e))
        data = {'success': False, 'otp': None}
        return data


def send_otp_without_twilio(contact):
    try:
        otp = random.randint(1000, 9999)
        data = {'success': True, 'otp': otp}
        user = CustomUser.objects.get(contact=contact)
        user.last_otp_status = "DELIVERED"
        user.save()
        logger_info.info(f'verification otp: {otp}')
        logger_info.info('Successfully verification code sent.')
        return data

    except Exception as e:
        logger_error.error('Invalid phone number entered' + str(e))
        data = {'success': False, 'otp': None}
        return data
