from django.contrib.auth import get_user_model
from django.db.models.signals import post_save
from django.dispatch import receiver

User = get_user_model()


@receiver(post_save, sender=User)
def _touch_profile(sender, instance: User, created: bool, **kwargs):
    # No creamos Profile automáticamente: el flujo de registro crea Profile con datos completos.
    # Esto evita perfiles "vacíos".
    return
