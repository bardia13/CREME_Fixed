from lib2to3.pytree import Base
from django.core.management.base import BaseCommand
from CREMEapplication.tasks_minimal import create_creme_object



class Command(BaseCommand):
    def handle(self, *args, **options):
        pass
