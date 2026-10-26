from django.db import models


class SecurityMutex(models.Model):
    """
    Single-row mutex table (id=1) created at migration time (DES-08).
    Locked via SELECT ... FOR UPDATE inside transaction.atomic() before any sensitive mutation.
    If row id=1 is missing, operations must fail-closed.
    """

    id = models.IntegerField(primary_key=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "common_securitymutex"

    def __str__(self) -> str:
        return f"SecurityMutex(id={self.id})"

