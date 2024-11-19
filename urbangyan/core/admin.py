from django.contrib import admin
from .models import User, Blog, Comment, Offer, Subject, Course, Unit, Topic, Quiz, QuizName, Questions, QuizResult, \
    UserSession, MockTestSubjectConfig, MockTest


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


admin.site.register(Blog, BlogAdmin)


# Registering Comment model
class CommentAdmin(admin.ModelAdmin):
    list_display = ('blog', 'author', 'created_at')
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


# Registering Quiz model
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
    list_display = ['id', 'user', 'duration', 'total_questions', 'total_max_score']
    inlines = [MockTestSubjectConfigInline]


from .models import Badge

@admin.register(Badge)
class BadgeAdmin(admin.ModelAdmin):
    list_display = ('user', 'mock_test', 'badge_type', 'date_awarded')  # Columns to display in the list view
    list_filter = ('badge_type', 'date_awarded')  # Filters for the list view
    search_fields = ('user__username', 'mock_test__Exam_Name', 'badge_type')  # Fields to search by
    ordering = ('-date_awarded',)  # Default ordering by date awarded (most recent first)

    # Optional: Customizing how fields are displayed in the form view
    fieldsets = (
        (None, {
            'fields': ('user', 'mock_test', 'badge_type')
        }),
        ('Award Information', {
            'fields': ('date_awarded',),
            'classes': ('collapse',),  # Optionally collapse this section
        }),
    )