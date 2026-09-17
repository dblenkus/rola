"""Supply the host migration node referenced by core.0010 for tests only."""
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [('drf_user', '0001_initial')]
    operations = []
