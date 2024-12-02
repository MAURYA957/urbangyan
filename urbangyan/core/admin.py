from django.contrib import admin
from .models import User, Blog, Comment, Offer, Subject, Course, Unit, Topic, Quiz, QuizName, Questions, QuizResult, \
    UserSession, MockTestSubjectConfig, MockTest, UserResponse


# Customizing the User admin
class UserAdmin(admin.ModelAdmin):
    list_display = ('username', 'first_name', 'last_name', 'email', 'is_staff_user', 'is_visitor', 'created_at')
    search_fields = ('username', 'email', 'first_name', 'last_name')
    ordering = ('created_at',)
    list_filter = ('is_staff_user', 'is_visitor', 'gender')


admin.site.register(User, UserAdmin)


# Registering Blog model
class BlogAdmin(admin.ModelAdmin):
    list_display = ('title', 'author', 'created_at', 'likes_count', 'shares_count', 'comment_count')
    search_fields = ('title', 'author__username')
    ordering = ('-created_at',)

    def delete_model(self, request, obj):
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"Deleting Blog: {obj} with related comments")
        super().delete_model(request, obj)

admin.site.register(Blog, BlogAdmin)


# Registering Comment model
class CommentAdmin(admin.ModelAdmin):
    list_display = ('content', 'author', 'created_at')
    search_fields = ('blog__title', 'author__username', 'content')
    ordering = ('-created_at',)


admin.site.register(Comment, CommentAdmin)


# Registering Offer model
class OfferAdmin(admin.ModelAdmin):
    list_display = ('code', 'discount_percent', 'valid_from', 'valid_until', 'created_by', 'created_on')
    search_fields = ('code',)
    ordering = ('valid_from',)


admin.site.register(Offer, OfferAdmin)


# Registering Subject model
class SubjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'description', 'authors')
    search_fields = ('name', 'authors')
    ordering = ('name',)


admin.site.register(Subject, SubjectAdmin)


# Registering Course model
class CourseAdmin(admin.ModelAdmin):
    list_display = ('title', 'price', 'created_at')
    search_fields = ('title',)
    ordering = ('-created_at',)


admin.site.register(Course, CourseAdmin)


# Registering Unit model
class UnitAdmin(admin.ModelAdmin):
    list_display = ('subject', 'title')
    search_fields = ('title',)
    ordering = ('title',)


admin.site.register(Unit, UnitAdmin)


# Registering Topic model
class TopicAdmin(admin.ModelAdmin):
    list_display = ('topic', 'staff', 'created_at')
    search_fields = ('topic', 'staff__username')
    ordering = ('-created_at',)


admin.site.register(Topic, TopicAdmin)


# Registering quiz model
class QuizAdmin(admin.ModelAdmin):
    list_display = ('quiz', 'subject')
    search_fields = ('quiz', 'subject')
    ordering = ('quiz',)


admin.site.register(Quiz, QuizAdmin)


# Registering QuizName model
class QuizNameAdmin(admin.ModelAdmin):
    list_display = ('quiz', 'quizname', 'duration', 'created_at')
    search_fields = ('quizname',)
    ordering = ('-created_at',)


admin.site.register(QuizName, QuizNameAdmin)


# Registering Questions model
class QuestionsAdmin(admin.ModelAdmin):
    list_display = ('quizname', 'question', 'created_at')
    search_fields = ('question',)
    ordering = ('-created_at',)


admin.site.register(Questions, QuestionsAdmin)


# Registering QuizResult model
class QuizResultAdmin(admin.ModelAdmin):
    list_display = ('user', 'quiz', 'score', 'submitted_at')
    search_fields = ('user__username', 'quiz__quiz')
    ordering = ('-submitted_at',)


admin.site.register(QuizResult, QuizResultAdmin)


# Registering UserSession model
class UserSessionAdmin(admin.ModelAdmin):
    list_display = ('user', 'session_key', 'logged_in_at', 'logged_out_at')
    search_fields = ('user__username', 'session_key')
    ordering = ('-logged_in_at',)


admin.site.register(UserSession, UserSessionAdmin)


class MockTestSubjectConfigInline(admin.TabularInline):
    model = MockTestSubjectConfig
    extra = 1


@admin.register(MockTest)
class MockTestAdmin(admin.ModelAdmin):
    list_display = ['Exam_Name', 'duration', 'total_questions', 'total_max_score']
    inlines = [MockTestSubjectConfigInline]


from .models import Badge


class BadgeAdmin(admin.ModelAdmin):
    list_display = (
    'id', 'user', 'badge_type', 'score', 'attempted_question', 'total_question', 'Incorrect_question', 'Unattampted_question',
    'exam_name', 'date_awarded')  # Fields to be displayed in the admin list view
    list_filter = ('badge_type', 'date_awarded', 'exam_name')  # Filters to help narrow down the data in the admin view
    search_fields = ('user__username', 'badge_type', 'exam_name')  # Fields that can be searched
    readonly_fields = ('submission_id', 'created_at', 'updated_at')  # Fields that should be read-only
    date_hierarchy = 'date_awarded'  # Allows the admin to filter data by date
    ordering = ('-date_awarded',)  # Default sort order

    # Optional: If you want to customize how data appears in the admin panel:
    def badge_type_display(self, obj):
        return f"{obj.badge_type.capitalize()}"  # This will capitalize the first letter of badge type

    badge_type_display.admin_order_field = 'badge_type'  # Allows sorting by badge type in the admin panel
    badge_type_display.short_description = 'Badge Type'

    fieldsets = (
        (None, {
            'fields': ('user', 'submission_id', 'score', 'attempted_question', 'total_question', 'Incorrect_question',
                       'Unattampted_question', 'mock_test', 'badge_type', 'exam_name', 'date_awarded', 'created_at',
                       'updated_at')
        }),
    )


# Register the Badge model and the BadgeAdmin class with the Django admin site
admin.site.register(Badge, BadgeAdmin)


class UserResponseAdmin(admin.ModelAdmin):
    list_display = (
        'id',  # Unique ID for easy reference
        'user',  # User who submitted the response
        'mock_test',  # Associated mock test
        'question',  # Associated question
        'selected_option',  # Option selected by the user
        'correct_answer',  # Correct option
        'is_correct',  # Whether the answer is correct
        'exam_name',  # Name of the exam
        'created_at',  # Submission time
        'updated_at',  # Last updated time
    )
    list_filter = (
        'is_correct',  # Filter responses by correctness
        'mock_test',  # Filter by mock test
        'created_at',  # Filter by submission date
    )
    search_fields = (
        'user__username',  # Search by username
        'mock_test__Exam_Name',  # Search by exam name
        'question__id',  # Search by question ID
    )
    readonly_fields = ('created_at', 'updated_at')  # Make timestamp fields read-only
    ordering = ('-created_at',)  # Order responses by most recent first
    fieldsets = (
        (None, {
            'fields': (
                'user',
                'mock_test',
                'question',
                'exam_name',
            )
        }),
        ('Response Details', {
            'fields': (
                'selected_option',
                'correct_answer',
                'is_correct',
                'answer_description',
                'explanation',
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
        }),
    )

    # Customize how the form fields are displayed
    def get_form(self, request, obj=None, **kwargs):
        form = super().get_form(request, obj, **kwargs)
        # If additional customization is needed, apply here
        return form


# Register the admin
admin.site.register(UserResponse, UserResponseAdmin)
