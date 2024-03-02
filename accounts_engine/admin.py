from django.contrib import admin
from accounts_engine.models import (CustomUser, InvalidatedToken, UserDonation)

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(InvalidatedToken)
admin.site.register(UserDonation)
