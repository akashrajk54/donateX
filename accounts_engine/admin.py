from django.contrib import admin
from accounts_engine.models import (CustomUser, InvalidatedToken)

# Register your models here.
admin.site.register(CustomUser)
admin.site.register(InvalidatedToken)
