# Generated by Django 4.2.16 on 2024-11-06 04:47

import ckeditor_uploader.fields
from django.conf import settings
import django.contrib.auth.models
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.CreateModel(
            name="User",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "last_login",
                    models.DateTimeField(
                        blank=True, null=True, verbose_name="last login"
                    ),
                ),
                (
                    "is_staff",
                    models.BooleanField(
                        default=False,
                        help_text="Designates whether the user can log into this admin site.",
                        verbose_name="staff status",
                    ),
                ),
                (
                    "is_active",
                    models.BooleanField(
                        default=True,
                        help_text="Designates whether this user should be treated as active. Unselect this instead of deleting accounts.",
                        verbose_name="active",
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(
                        default=django.utils.timezone.now, verbose_name="date joined"
                    ),
                ),
                ("username", models.CharField(max_length=100, unique=True)),
                ("first_name", models.CharField(blank=True, max_length=100)),
                ("middle_name", models.CharField(blank=True, max_length=100)),
                ("last_name", models.CharField(max_length=100)),
                (
                    "bio",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=1000),
                ),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("phone", models.CharField(blank=True, max_length=15)),
                ("address", models.CharField(blank=True, max_length=100)),
                ("country", models.CharField(default="De_data", max_length=100)),
                ("state", models.CharField(default="De_data", max_length=100)),
                ("city", models.CharField(default="De_data", max_length=100)),
                ("pin", models.CharField(default="De_data", max_length=10)),
                ("password", models.CharField(max_length=128)),
                ("user_type", models.CharField(default="De_data", max_length=50)),
                ("gender", models.CharField(default="De_data", max_length=100)),
                ("image", models.ImageField(blank=True, upload_to="user")),
                ("is_superuser", models.BooleanField(default=False)),
                ("is_staff_user", models.BooleanField(default=False)),
                ("is_visitor", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True, related_name="custom_user_set", to="auth.group"
                    ),
                ),
                (
                    "user_permissions",
                    models.ManyToManyField(
                        blank=True,
                        related_name="custom_user_permissions_set",
                        to="auth.permission",
                    ),
                ),
            ],
            options={
                "permissions": [("can_view_user", "Can view user")],
                "unique_together": {("username",)},
            },
            managers=[
                ("objects", django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name="Blog",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("title", models.CharField(max_length=200)),
                (
                    "content",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=2000),
                ),
                ("image", models.ImageField(blank=True, upload_to="blog")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("likes_count", models.PositiveIntegerField(default=0)),
                ("shares_count", models.PositiveIntegerField(default=0)),
                ("comment_count", models.PositiveIntegerField(default=0)),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="blogs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Course",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "title",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=255),
                ),
                (
                    "description",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, null=True
                    ),
                ),
                (
                    "image",
                    models.ImageField(blank=True, null=True, upload_to="courses/"),
                ),
                ("price", models.DecimalField(decimal_places=2, max_digits=10)),
                ("Staff", models.CharField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name="MockTest",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("Exam_Name", models.CharField(default="test", max_length=100)),
                (
                    "Instructions",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        default="test", max_length=1000
                    ),
                ),
                ("duration", models.DurationField()),
                ("total_questions", models.PositiveIntegerField(default=0)),
                ("total_max_score", models.PositiveIntegerField(default=0)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="quiz",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("quiz", models.CharField(max_length=500)),
                ("description", ckeditor_uploader.fields.RichTextUploadingField()),
                ("image", models.ImageField(blank=True, upload_to="quiz")),
                (
                    "course",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="quizzes",
                        to="core.course",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Subject",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("name", models.CharField(max_length=255)),
                (
                    "description",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, null=True
                    ),
                ),
                (
                    "image",
                    models.ImageField(blank=True, null=True, upload_to="subjects/"),
                ),
                (
                    "authors",
                    models.TextField(
                        blank=True,
                        help_text="Enter author names separated by commas",
                        null=True,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="UserSession",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "session_key",
                    models.CharField(max_length=40, null=True, unique=True),
                ),
                ("logged_in_at", models.DateTimeField(auto_now_add=True)),
                ("logged_out_at", models.DateTimeField(blank=True, null=True)),
                ("last_accessed", models.DateTimeField(auto_now=True)),
                ("username", models.CharField(blank=True, max_length=150)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Unit",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "title",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=255),
                ),
                (
                    "description",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, null=True
                    ),
                ),
                (
                    "table_of_contents",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, null=True
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "subject",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="units",
                        to="core.subject",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Topic",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("topic", models.CharField(max_length=200)),
                (
                    "description",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, null=True
                    ),
                ),
                (
                    "image",
                    models.ImageField(
                        blank=True, null=True, upload_to="topics/images/"
                    ),
                ),
                (
                    "file",
                    models.FileField(blank=True, null=True, upload_to="topics/files/"),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "course",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="topics",
                        to="core.course",
                    ),
                ),
                (
                    "staff",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="topics",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "subject",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="topics",
                        to="core.subject",
                    ),
                ),
                (
                    "unit",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="topics",
                        to="core.unit",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="QuizResult",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("total_questions", models.IntegerField()),
                ("attempted_questions", models.IntegerField()),
                ("correct_answers", models.IntegerField()),
                ("wrong_answers", models.IntegerField()),
                ("score", models.IntegerField()),
                ("submitted_at", models.DateTimeField(auto_now_add=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "quiz",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="core.quiz"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="QuizName",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "quizname",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        default="None", max_length=100
                    ),
                ),
                ("duration", models.IntegerField(default=60)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "quiz",
                    models.ForeignKey(
                        default="None",
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="quizname",
                        to="core.quiz",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Questions",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("question_level", models.CharField(default="Beginner", max_length=50)),
                (
                    "question",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=500),
                ),
                (
                    "option_1",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=100),
                ),
                (
                    "option_2",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=100),
                ),
                (
                    "option_3",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=100),
                ),
                (
                    "option_4",
                    ckeditor_uploader.fields.RichTextUploadingField(max_length=100),
                ),
                ("answer", models.IntegerField()),
                (
                    "explanation",
                    ckeditor_uploader.fields.RichTextUploadingField(
                        blank=True, max_length=1000, null=True
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "Subject",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="questions",
                        to="core.subject",
                    ),
                ),
                (
                    "quiz",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="questions",
                        to="core.quiz",
                    ),
                ),
                (
                    "quizname",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="questions",
                        to="core.quizname",
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="Offer",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("code", models.CharField(max_length=50, unique=True)),
                (
                    "discount_percent",
                    models.DecimalField(decimal_places=2, max_digits=5),
                ),
                ("valid_from", models.DateTimeField()),
                ("valid_until", models.DateTimeField()),
                ("created_on", models.DateTimeField(auto_now_add=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="created_offers",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
        ),
        migrations.CreateModel(
            name="MockTestSubjectConfig",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("num_questions", models.PositiveIntegerField()),
                ("max_score", models.PositiveIntegerField()),
                (
                    "mock_test",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="subject_configs",
                        to="core.mocktest",
                    ),
                ),
                (
                    "subject",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="core.subject"
                    ),
                ),
            ],
        ),
        migrations.AddField(
            model_name="course",
            name="subjects",
            field=models.ManyToManyField(related_name="courses", to="core.subject"),
        ),
        migrations.CreateModel(
            name="Comment",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("content", ckeditor_uploader.fields.RichTextUploadingField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "author",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "blog",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="comments",
                        to="core.blog",
                    ),
                ),
            ],
        ),
    ]
