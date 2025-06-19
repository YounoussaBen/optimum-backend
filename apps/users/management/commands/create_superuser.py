# Create this file: apps/users/management/commands/create_superuser_if_none.py

import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand

User = get_user_model()


class Command(BaseCommand):
    help = "Creates a superuser if none exist"

    def handle(self, *args, **options):
        if User.objects.filter(is_superuser=True).exists():
            self.stdout.write(self.style.SUCCESS("Superuser already exists."))
            return

        email = os.environ.get("SUPERUSER_EMAIL")
        password = os.environ.get("SUPERUSER_PASSWORD")

        if not email or not password:
            self.stdout.write(
                self.style.ERROR(
                    "SUPERUSER_EMAIL and SUPERUSER_PASSWORD environment variables are required"
                )
            )
            return

        try:
            User.objects.create_superuser(
                email=email,
                password=password,
            )
            self.stdout.write(
                self.style.SUCCESS(f"Superuser created with email: {email}")
            )
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error creating superuser: {e}"))
