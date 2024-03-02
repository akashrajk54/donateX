import logging
from django.http import JsonResponse

from accounts_engine.utils import success_false_response
from accounts_engine.models import InvalidatedToken
logger = logging.getLogger(__name__)
logger_info = logging.getLogger('info')
logger_error = logging.getLogger('error')


class TokenInvalidatedMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        try:
            auth_header = request.META.get('HTTP_AUTHORIZATION')
            token = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else auth_header
            if token in InvalidatedToken.objects.values_list('token', flat=True):
                logger_info.info(f'Token: {token} is invalid.')
                response_data = success_false_response(message='Please login.')
                response = JsonResponse(response_data, status=401)
                return response

        except Exception as e:
            pass

        response = self.get_response(request)
        return response
