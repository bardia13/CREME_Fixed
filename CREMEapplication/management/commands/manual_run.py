from lib2to3.pytree import Base
from django.core.management.base import BaseCommand
from CREMEapplication.tasks_minimal import create_creme_object, update_testbed_status



class RunCommand(BaseCommand):
    def handle(self, *args, **options):
        creme = create_creme_object()
        print("Executing full run based on the data available in the dataset ...")
        update_testbed_status(2)
        creme.run()
        update_testbed_status(3)