from django.contrib.auth.base_user import BaseUserManager
from django.utils.translation import gettext_lazy as _


class CustomUserManager(BaseUserManager):
    """
    Custom user model manager where contact is the unique identifiers
    for authentication instead of usernames.
    """
    def create_user(self, contact, password=None, **extra_fields):
        """
        Create and save a User with the given contact and password.
        """
        if not contact:
            raise ValueError(_('The Contact must be set'))
        contact = self.normalize_email(contact)
        user = self.model(contact=contact, **extra_fields)
        # user.set_password(password)

        # Set the password to an empty string if it's not provided
        if password is not None:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save()
        return user

    def create_superuser(self, contact, password, **extra_fields):
        """
        Create and save a SuperUser with the given contact and password.
        """
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(contact, password, **extra_fields)
