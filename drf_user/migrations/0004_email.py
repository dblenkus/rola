# Generated by Django 3.0rc1 on 2020-07-26 18:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('drf_user', '0003_auto_20200724_2119'),
    ]

    operations = [
        migrations.CreateModel(
            name='Email',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('subject', models.CharField(max_length=100)),
                ('body', models.TextField()),
                ('html_body', models.TextField(blank=True, null=True)),
            ],
        ),
    ]
