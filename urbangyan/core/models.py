import uuid
from datetime import timedelta, datetime
from random import random

from django.conf import settings
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.db import models
from django.db.models import Sum
from django.middleware.csrf import logger
from django.urls import reverse
from ckeditor_uploader.fields import RichTextUploadingField


class User(AbstractUser):
    username = models.CharField(max_length=100, unique=True)
    first_name = models.CharField(max_length=100, blank=True)
    middle_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100)
    profile = RichTextUploadingField(max_length=1000, null=True, blank=True)
    email = models.EmailField(unique=True)  # Ensure email is unique
    phone = models.CharField(max_length=15, blank=True)  # Allow blank
    address = models.CharField(max_length=100, blank=True)  # Allow blank
    country = models.CharField(max_length=100, default='De_data')
    state = models.CharField(max_length=100, default='De_data')
    city = models.CharField(max_length=100, default='De_data')
    pin = models.CharField(max_length=10, default='De_data')  # Rename to lowercase 'pin'
    password = models.CharField(max_length=128)  # Use max_length=128 for hashed passwords
    user_type = models.CharField(max_length=50, default='De_data')  # Renamed to avoid conflict with built-in type
    gender = models.CharField(max_length=100, default='De_data')
    image = models.ImageField(upload_to='user', blank=True)  # Allow blank images
    is_superuser = models.BooleanField(default=False)  # Inherited from AbstractUser
    is_staff_user = models.BooleanField(default=False)
    is_visitor = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        # Ensure is_visitor is always True for new users
        if not self.pk:  # Only set this for new instances
            self.is_visitor = True
        super().save(*args, **kwargs)

    groups = models.ManyToManyField(
        Group,
        related_name='custom_user_set',  # Change related_name to avoid conflict
        blank=True,
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='custom_user_permissions_set',  # Change related_name to avoid conflict
        blank=True,
    )

    class Meta:
        unique_together = ('username',)
        permissions = [('can_view_user', 'Can view user')]

    def __str__(self):
        return self.first_name


class Blog(models.Model):
    title = models.CharField(max_length=200)
    content = RichTextUploadingField(max_length=2000)
    image = models.ImageField(upload_to='blog', blank=True)
    author = models.ForeignKey(User, on_delete=models.CASCADE, related_name='blogs')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    likes_count = models.PositiveIntegerField(default=0)  # To store like counts
    shares_count = models.PositiveIntegerField(default=0)  # To store share counts
    comment_count = models.PositiveIntegerField(default=0)  # To store comment counts

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse('blog-detail-template', args=[self.id])


class Comment(models.Model):
    blog = models.ForeignKey(Blog, related_name='comments', on_delete=models.CASCADE)
    content = RichTextUploadingField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.content


class Offer(models.Model):
    code = models.CharField(max_length=50, unique=True)  # Offer code
    discount_percent = models.DecimalField(max_digits=5, decimal_places=2)  # Discount percentage
    valid_from = models.DateTimeField()
    valid_until = models.DateTimeField()
    created_by = models.ForeignKey('User', on_delete=models.SET_NULL, null=True, blank=True,
                                   related_name='created_offers')  # The user who created the offer
    created_on = models.DateTimeField(auto_now_add=True)  # Automatically set the creation time

    def __str__(self):
        return f"{self.code} - {self.discount_percent}%"


class Subject(models.Model):
    name = models.CharField(max_length=255)
    description = RichTextUploadingField(blank=True, null=True)
    image = models.ImageField(upload_to='subjects/', blank=True, null=True)  # Optional image for Subject
    authors = models.TextField(blank=True, null=True,
                               help_text="Enter author names separated by commas")  # Store multiple author names
    is_active = models.BooleanField(default=True)

    def delete(self, *args, **kwargs):
        self.is_active = False
        self.save()

    def __str__(self):
        return self.name

    def get_author_list(self):
        """Convert comma-separated author names to a list"""
        return [author.strip() for author in self.authors.split(',')] if self.authors else []

    def __str__(self):
        return self.name


class Course(models.Model):
    title = RichTextUploadingField(max_length=255)
    description = RichTextUploadingField(blank=True, null=True)
    image = models.ImageField(upload_to='courses/', blank=True, null=True)
    price = models.DecimalField(max_digits=10, decimal_places=2)
    subjects = models.ManyToManyField('Subject', related_name='courses')  # Many-to-many relationship with Subject
    Staff = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    def get_final_price(self, offer=None):
        """Calculate final price after applying an offer."""
        if offer:
            discount_amount = (self.price * offer.discount_percent) / 100
            return self.price - discount_amount
        return self.price


class Unit(models.Model):
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='units')
    title = RichTextUploadingField(max_length=255)
    description = RichTextUploadingField(blank=True, null=True)
    table_of_contents = RichTextUploadingField(blank=True, null=True)  # New field for table of contents
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title


class Topic(models.Model):
    topic = models.CharField(max_length=200)
    subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='topics', blank=True, null=True)
    unit = models.ForeignKey(Unit, on_delete=models.CASCADE, related_name='topics', blank=True, null=True)
    description = RichTextUploadingField(blank=True, null=True)  # Enable rich text editor
    image = models.ImageField(upload_to='topics/images/', blank=True, null=True)  # Optional image for Topic
    file = models.FileField(upload_to='topics/files/', blank=True, null=True)  # File like PDF
    staff = models.ForeignKey(User, on_delete=models.CASCADE, related_name='topics')
    created_at = models.DateTimeField(auto_now_add=True)  # Automatically set on creation
    updated_at = models.DateTimeField(auto_now=True)  # Automatically set on every update

    def __str__(self):
        return self.topic


class Quiz(models.Model):
    quiz = models.CharField(max_length=500)
    description = RichTextUploadingField()
    subject = models.ForeignKey(
        Subject,
        on_delete=models.SET_NULL,  # Set subject to NULL if it's deleted
        related_name='quizzes',  # Adjusted for a plural-related name
        blank=True,
        null=True
    )
    No_of_Questions = models.IntegerField(default=10)
    duration = models.DurationField(default=timedelta(minutes=30))  # Duration in minutes
    created_at = models.DateTimeField(auto_now_add=True, blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, blank=True, null=True)

    def __str__(self):
        return self.quiz

    def __str__(self):
        return self.quiz


class Questions(models.Model):
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE, related_name='questions')
    Subject = models.ForeignKey(Subject, on_delete=models.CASCADE, related_name='questions')
    question_level = models.CharField(max_length=50, default='Beginner')  # Example default level
    question = RichTextUploadingField(max_length=500)
    option_1 = RichTextUploadingField(max_length=100)
    option_2 = RichTextUploadingField(max_length=100)
    option_3 = RichTextUploadingField(max_length=100)
    option_4 = RichTextUploadingField(max_length=100)
    answer = models.IntegerField()  # Now change it to IntegerField
    explanation = RichTextUploadingField(max_length=1000, null=True,
                                         blank=True)  # for answer explanation added on 21/10/2024
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.question


class QuizResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    quiz = models.ForeignKey(Quiz, on_delete=models.CASCADE)
    total_questions = models.IntegerField()
    attempted_questions = models.IntegerField()
    correct_answers = models.IntegerField()
    wrong_answers = models.IntegerField()
    score = models.IntegerField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.quiz.quiz} - {self.score}"


class UserSession(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    session_key = models.CharField(max_length=40, unique=True, null=True)
    logged_in_at = models.DateTimeField(auto_now_add=True)
    logged_out_at = models.DateTimeField(null=True, blank=True)
    last_accessed = models.DateTimeField(auto_now=True)  # Remove default=None
    username = models.CharField(max_length=150, blank=True)  # Set blank=True if you want it to be optional

    def save(self, *args, **kwargs):
        # Automatically set the username field from the user when saving
        if not self.username:
            self.username = self.user.username
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Session {self.session_key} for {self.username}"


class MockTestSubjectConfig(models.Model):
    mock_test = models.ForeignKey('MockTest', on_delete=models.CASCADE, related_name='subject_configs')
    subject = models.ForeignKey('Subject', on_delete=models.CASCADE, related_name='mock_test_subject_configs')
    num_questions = models.PositiveIntegerField()  # Number of questions for this subject
    max_score = models.PositiveIntegerField()  # Maximum score for this subject in the test

    def __str__(self):
        return f"{self.num_questions} questions from {self.subject.name} with max score {self.max_score}"


class MockTest(models.Model):
    Exam_Name = models.CharField(max_length=100, default='test')
    Instructions = RichTextUploadingField(max_length=1000, default='test')
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    duration = models.DurationField()
    total_questions = models.PositiveIntegerField(default=0)
    total_max_score = models.PositiveIntegerField(default=0)
    negative_mark = models.FloatField(default=0.0)
    questions = models.ManyToManyField('Questions', related_name='mock_tests')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Mock Test ({self.id}) - Duration: {self.duration}"

    def populate_questions(self):
        configs = self.subject_configs.all()
        self.total_questions = configs.aggregate(total_q=Sum('num_questions'))['total_q'] or 0
        self.total_max_score = configs.aggregate(total_score=Sum('max_score'))['total_score'] or 0

        selected_questions = []
        for config in configs:
            subject_questions = list(Questions.objects.filter(subject=config.subject))
            sampled_questions = random.sample(subject_questions, min(len(subject_questions), config.num_questions))
            selected_questions.extend(sampled_questions)

        self._set_questions(selected_questions)  # Set questions without calling save

    def _set_questions(self, questions):
        # Helper method to set questions without triggering save
        self.questions.set(questions)

    def save(self, *args, **kwargs):
        # Avoid recursion by checking if the object is new
        is_new_instance = self.pk is None
        super().save(*args, **kwargs)  # Call the original save()

        if is_new_instance:
            self.populate_questions()  # Only populate on initial save
            super().save(update_fields=['total_questions', 'total_max_score'])  # Save totals without recursion


class UserResponse(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    mock_test = models.ForeignKey(MockTest, on_delete=models.CASCADE, null=True, blank=True)
    question = models.ForeignKey(Questions, on_delete=models.CASCADE, null=True, blank=True)
    submission_id = models.UUIDField(default=uuid.uuid4, editable=False)  # Unique submission ID
    correct_answer = models.IntegerField(null=True, blank=True)  # Option number (1-4)
    explanation = RichTextUploadingField(max_length=1000, null=True, blank=True)
    selected_option = models.IntegerField()  # User's selected option (1-4)
    answer_description = RichTextUploadingField(max_length=1000, null=True,
                                                blank=True)  # Explanation based on user input
    is_correct = models.BooleanField(default=False)
    exam_name = models.CharField(max_length=255, null=True, blank=True)  # Changed from RichText to CharField
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f"Response by {self.user} for Question ID {self.question.id if self.question else 'N/A'}"

    def __str__(self):
        return f"Response by {self.user} for Question ID {self.question.id if self.question else 'N/A'}"

    def save(self, *args, **kwargs):
        logger.debug(f"Starting save process for UserResponse ID: {self.id if self.id else 'New Instance'}")

        if not self.mock_test or not self.question:
            logger.error("MockTest or Question is missing during save.")
            raise ValueError("MockTest and Question are required fields.")

        # Validate the selected option
        if self.selected_option not in [0, 1, 2, 3, 4]:
            logger.error(f"Invalid selected option: {self.selected_option}. Must be between 1 and 4.")
            raise ValueError("Selected option must be between 1 and 4.")

        # Populate fields if not explicitly set
        self._populate_correct_answer_and_explanation()
        self._populate_exam_name()
        self._check_correctness()
        self._populate_answer_description()

        # Call superclass save
        try:
            logger.debug("Saving UserResponse to the database.")
            super().save(*args, **kwargs)
            logger.debug("Save successful.")
        except Exception as e:
            logger.error(f"Error saving UserResponse: {e}")
            raise

    def _populate_correct_answer_and_explanation(self):
        if self.correct_answer is None:
            self.correct_answer = self.question.answer
            logger.debug(f"Set correct_answer: {self.correct_answer}")

        if self.explanation is None:
            self.explanation = self.question.explanation
            logger.debug(f"Set explanation: {self.explanation}")

    def _populate_exam_name(self):
        if self.exam_name is None and self.mock_test:
            self.exam_name = self.mock_test.Exam_Name
            logger.debug(f"Set exam_name: {self.exam_name}")

    def _check_correctness(self):
        self.is_correct = self.selected_option == self.correct_answer
        logger.debug(
            f"Set is_correct: {self.is_correct} (Selected: {self.selected_option}, Correct: {self.correct_answer})")

    def _populate_answer_description(self):
        options_map = {
            1: self.question.option_1,
            2: self.question.option_2,
            3: self.question.option_3,
            4: self.question.option_4,
        }
        self.answer_description = options_map.get(self.selected_option, "Invalid selection.")
        logger.debug(f"Set answer_description: {self.answer_description}")


class Badge(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    submission_id = models.UUIDField(default=uuid.uuid4, editable=False)  # Unique submission ID
    score = models.IntegerField(default=0)  # Changed to IntegerField
    attempted_question = models.IntegerField(default=0)  # Changed to IntegerField
    total_question = models.IntegerField(default=0)  # Changed to IntegerField
    Incorrect_question = models.IntegerField(default=0)  # Changed to IntegerField
    Unattampted_question = models.IntegerField(default=0)  # Changed to IntegerField
    mock_test = models.ForeignKey(MockTest, on_delete=models.CASCADE)
    badge_type = models.CharField(max_length=100)
    date_awarded = models.DateTimeField(auto_now_add=True)
    exam_name = models.CharField(max_length=255, null=True, blank=True)  # Changed from RichText to CharField
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True, null=True, blank=True)

    def __str__(self):
        return f"{self.user} earned {self.badge_type} badge"


class Advertisement(models.Model):
    MEDIA_CHOICES = [
        ('image', 'Image'),
        ('audio', 'Audio'),
        ('video', 'Video'),
        ('google', 'Google Ad'),
    ]

    title = models.CharField(max_length=200, help_text="Title of the advertisement.")
    media_type = models.CharField(max_length=10, choices=MEDIA_CHOICES, default='image',
                                  help_text="Type of media for the advertisement.")
    media_file = models.FileField(upload_to='advertisements/', blank=True, null=True,
                                  help_text="Media file for the advertisement (image, audio, or video).")
    google_ad_code = models.TextField(blank=True, null=True, help_text="Google Ad code (if applicable).")
    url = models.URLField(blank=True, null=True, help_text="URL the advertisement links to.")
    is_active = models.BooleanField(default=True,
                                    help_text="Automatically deactivates if the current date exceeds the expiry date.")
    expiry_date = models.DateTimeField(blank=True, null=True,
                                       help_text="Expiry date for the advertisement. Leave blank for no expiry.")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

    def is_expired(self):
        """Check if the advertisement is expired."""
        from django.utils.timezone import now
        return self.expiry_date and self.expiry_date < now()

    def save(self, *args, **kwargs):
        """Override save method to update is_active based on expiry date."""
        from django.utils.timezone import now
        if self.expiry_date and self.expiry_date <= now():
            self.is_active = False
        super().save(*args, **kwargs)


# Example usage in views
# Fetch active and non-expired advertisements for a specific page
# from django.utils.timezone import now
# ads = Advertisement.objects.filter(pages__slug='home', is_active=True).exclude(expiry_date__lt=now())


class JobType(models.Model):
    name = models.CharField(max_length=50, unique=True, help_text="Type of job (e.g., Sarkari, Private).")

    def __str__(self):
        return self.name

class JobCategory(models.Model):
    name = models.CharField(max_length=100, unique=True, help_text="Category of the job (e.g., Engineering, Medical).")

    def __str__(self):
        return self.name

class JobStage(models.Model):
    name = models.CharField(max_length=50, unique=True, help_text="Stage of the job process (e.g., Advertised, Result Declared).")

    def __str__(self):
        return self.name

class ExperienceLevel(models.Model):
    level = models.CharField(max_length=50, unique=True, help_text="Name of the experience level (e.g., Entry-level, Mid-level).")
    created_at = models.DateTimeField(auto_now_add=True, help_text="The date and time when the experience level was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The date and time when the experience level was last updated.")



class Job(models.Model):
    job_type = models.ForeignKey(JobType, on_delete=models.PROTECT, help_text="Type of job (Sarkari or Private).")
    job_category = models.ForeignKey(JobCategory, on_delete=models.PROTECT, help_text="Category of the job.")
    ExperienceLevel = models.ForeignKey(ExperienceLevel, on_delete=models.PROTECT, blank=True, null=True, help_text="ExperienceLevel required for the job.")
    recruiter = models.CharField(max_length=100, help_text="Recruiter for the job.")
    advertised_no = models.CharField(max_length=100, help_text="Advertisement number.")
    exam_name = models.CharField(max_length=200, help_text="Name of the exam.")
    post_name = RichTextUploadingField(max_length=200, help_text="Name of the post.")
    total_post = models.PositiveIntegerField(help_text="Total number of posts available.")
    eligibility = RichTextUploadingField(help_text="Eligibility criteria for the job.")
    important_date = RichTextUploadingField(help_text="Important dates related to the job.")
    stage = models.ForeignKey(JobStage, on_delete=models.PROTECT, help_text="Current stage of the job.")
    notification = models.FileField(upload_to='notification/', blank=True, null=True, help_text="Notification details.")
    details = RichTextUploadingField(help_text="Detailed description of the job.")
    apply_link = models.URLField(blank=True, null=True, help_text="Link to apply for the job.")
    admit_card_link = models.URLField(blank=True, null=True, help_text="Link to download the admit card.")
    result_link = models.URLField(blank=True, null=True, help_text="Link to check the result.")
    official_website = models.URLField(help_text="Official website for the job.")

    created_at = models.DateTimeField(auto_now_add=True, help_text="The date and time when the job was created.")
    updated_at = models.DateTimeField(auto_now=True, help_text="The date and time when the job was last updated.")

    def __str__(self):
        return f"{self.exam_name} - {self.post_name}"


class SavedJob(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, help_text="The user who saved the job.")
    job_link = models.URLField(help_text="Link to the saved job.")
    created_at = models.DateTimeField(auto_now_add=True, help_text="The date and time when the job was saved.")

    def __str__(self):
        return f"SavedJob by {self.user.username} - {self.job_link}"

from django.contrib.contenttypes.models import ContentType

class Cart(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    product_type = models.ForeignKey(ContentType, on_delete=models.CASCADE)
    product_id = models.PositiveIntegerField()
    product = GenericForeignKey('product_type', 'product_id')
    quantity = models.PositiveIntegerField(default=1)

    def total_price(self):
        return self.product.price * self.quantity

    def __str__(self):
        return f"{self.product} ({self.quantity})"

class Order(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    total_amount = models.DecimalField(max_digits=10, decimal_places=2)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    valid_until = models.DateTimeField(blank=True, null=True)

    def save(self, *args, **kwargs):
        # Set the validity period to 1 year after the order is created
        if not self.valid_until:
            self.valid_until = self.created_at + timedelta(days=365)
        super().save(*args, **kwargs)

    def __str__(self):
        return f"Order {self.id} - {self.user.username}"