# Generated by Django 4.2.16 on 2024-11-18 12:37

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0005_userresponse_badge"),
    ]

    operations = [
        migrations.AlterField(
            model_name="mocktestsubjectconfig",
            name="subject",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name="mock_test_subject_configs",
                to="core.subject",
            ),
        ),
    ]
