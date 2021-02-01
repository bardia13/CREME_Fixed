from django.contrib import admin
from .models import Testbed, DataLoggerServer, TargetServer, BenignServer, VulnerableClient, NonVulnerableClient, \
    AttackerServer, MaliciousClient, AttackScenario

# Register your models here.
admin.site.register(Testbed)
admin.site.register(DataLoggerServer)
admin.site.register(TargetServer)
admin.site.register(BenignServer)
admin.site.register(VulnerableClient)
admin.site.register(NonVulnerableClient)
admin.site.register(AttackerServer)
admin.site.register(MaliciousClient)
admin.site.register(AttackScenario)