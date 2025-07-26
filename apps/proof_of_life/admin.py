from django.contrib import admin

from .models import (
    ProofOfLifeAuditLog,
    ProofOfLifePendingVerification,
    ProofOfLifeSettings,
    ProofOfLifeVerification,
)

admin.site.register(ProofOfLifePendingVerification)
admin.site.register(ProofOfLifeVerification)
admin.site.register(ProofOfLifeSettings)
admin.site.register(ProofOfLifeAuditLog)
