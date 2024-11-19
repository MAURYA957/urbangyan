from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from django.views.generic import TemplateView
from . import views
from .views import (
    BlogViewSet,
    CourseViewSet,
    TopicViewSet,
    QuizViewSet,
    UserRegistrationView,
    UserUpdateView,
    CustomTokenObtainPairView, UsernameAvailabilityView,
    QuestionsViewSet, login,
    LoginAPIView,
    dashboard_view, logout, UserSessionListCreateAPIView, UserSessionDetailAPIView, get_quiznames,
    update_quizname, delete_quizname, topic_user, SubjectViewSet, UnitViewSet, OfferCreateAPIView, OfferUpdateAPIView,
    OfferDeleteAPIView, OfferManagement, get_units, MockTestViewSet, MockTestListView,
    MockTestCreateView, MockTestUpdateView, MockTestDeleteView, MockTest_user, test_submit,
    mocktest_detailview
)
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf import settings
from django.conf.urls.static import static



# Schema view for Swagger documentation
schema_view = get_schema_view(
    openapi.Info(
        title="Urban Gyan",
        default_version='v1',
        description="API documentation for www.urbangyan.com",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="info@urbangyan.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)


# Setting up the router for the viewsets
router = DefaultRouter()
router.register(r'blogs', BlogViewSet, basename='blog')
router.register(r'courses', CourseViewSet, basename='course')
router.register(r'topics', TopicViewSet, basename='topic')
router.register(r'quizzes', QuizViewSet, basename='quiz')
router.register(r'questions', QuestionsViewSet, basename='question')
router.register(r'subjects', SubjectViewSet, basename='subject')
router.register(r'units', UnitViewSet, basename='unit')
router.register(r'mocktests', MockTestViewSet, basename='mocktests')

# Defining the URL patterns
urlpatterns = [

    # Home view
    path('', dashboard_view, name='dashboard'),
    path('login/', login, name='login'),
    path('logout/', logout, name='logout'),
    #path('ckeditor/', include('ckeditor_uploader.urls')),

    #User Session links,
    path('api/sessions/', UserSessionListCreateAPIView.as_view(), name='session-list-create'),
    path('api/sessions/<int:pk>/', UserSessionDetailAPIView.as_view(), name='session-detail'),


    # User registration URL
    path('api/users/', UserRegistrationView.as_view(), name='user_registration'),
    path('api/login/', LoginAPIView.as_view(), name='login_api'),
    path('api/username_availability/', UsernameAvailabilityView.as_view(), name='username_availability'),

    # User update URL
    path('api/users/<int:pk>/', UserUpdateView.as_view(), name='user_update'),

    # API URLs
    path('api/', include(router.urls)),  # Include the router URLs under 'api/'

    # Token URLs
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Swagger URLs
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),

    # Blog URLs
    path('blogs/', views.list_blogs_view, name='blogs-list-template'),
    path('blog_user/', views.Blog_user, name='blog_user'),
    path('blogs/create/', views.create_blog_view, name='blog-create-template'),
    path('blogs/<int:pk>/update/', views.update_blog_view, name='blog-update-template'),
    path('blogs/<int:pk>/delete/', views.delete_blog_view, name='blog-delete-template'),
    path('blogs/<int:pk>/', views.retrieve_blog_view, name='blog-detail-template'),
    path('blogs/<int:blog_id>/like/', views.like_blog, name='like-blog'),  # Add this URL for liking a blog
    path('blogs/<int:blog_id>/comment/', views.comment_blog, name='comment-blog'),  # Add this URL for commenting on a blog

    # User management URLs
    path('create_user/', TemplateView.as_view(template_name='create_user.html'), name='create_user'),
    path('update_user/', TemplateView.as_view(template_name='update_user.html'), name='update_user'),
    path('delete_user/', TemplateView.as_view(template_name='delete_user.html'), name='delete_user'),

    # Questions URLs
    path('questions/', views.list_questions_view, name='questions-list-template'),
    path('questions/create/', views.create_question_view, name='question-create-template'),
    path('questions/<int:pk>/update/', views.update_question_view, name='question-update-template'),
    path('questions/<int:pk>/delete/', views.delete_question_view, name='question-delete-template'),
    path('questions_view/', views.list_questions_view, name='questions-list-template'),

    # Quiz list and detail views
    path('questions_view/<int:quizname_id>/', views.questions_view, name='questions_view'),
    # View to display the quiz and questions
    path('questions_view/<int:quizname_id>/submit/', views.questions_submit, name='questions_submit'),
    # URL to handle quiz submission

    # URL to save result (if you have result-saving logic)
    path('questions_view/<int:quizname_id>/save-result/', views.questions_submit, name='save-questions-result'),


    #Quize template url
    path('quizzes/', views.list_quizzes_view, name='quiz-list-template'),
    path('quiz_view/', views.user_quizzes_view, name='user_quizzes_view'),
    path('quizzes/create/', views.create_quiz_view, name='quiz-create-template'),
    path('quizzes/<int:pk>/update/', views.update_quiz_view, name='quiz-update-template'),
    path('quizzes/<int:pk>/delete/', views.delete_quiz_view, name='quiz-delete-template'),
    #path('quiz_view/<int:quiz_id>/', views.quiz_view, name='quiz_view'),

    # quizname urls URLs
    path('quizname_user/<int:quiz_id>/', views.quizname_user, name='quizname_user'),
    path('quizlistview/', views.quiznamelist, name='quizlistview'),
    path('createquizname/', views.create_quizename_view, name='create_quizname'),
    path('get-quiznames/', get_quiznames, name='get-quiznames'),
    path('quizname/update/<int:pk>/', update_quizname, name='update_quizname'),
    path('quizname/delete/<int:pk>/', delete_quizname, name='delete_quizname'),

    # Course  User URLs
    path('course_user/', views.course_user, name='course-user-template'),
    path('course_user/<int:course_id>/', topic_user, name='topic-user-template'),  # Make sure to use course_id,
    path('courses/', views.list_courses_view, name='course-list-template'),
    path('courses/create/', views.create_course_view, name='course-create-template'),
    path('courses/<int:pk>/update/', views.update_course_view, name='course-update-template'),
    path('courses/<int:pk>/delete/', views.delete_course_view, name='course-delete-template'),

    # Topic URLs
    path('topics/', views.list_topics_view, name='topic-list-template'),
    path('topics/create/', views.create_topic_view, name='topic-create-template'),
    path('topics/<int:pk>/update/', views.update_topic_view, name='topic-update-template'),
    path('topics/<int:pk>/delete/', views.delete_topic_view, name='topic-delete-template'),
    path('get-units/<int:subject_id>/', get_units, name='get_units'),
    # Subject URLs (for templates)
    path('subjects/', views.list_subjects_view, name='subject-list-template'),
    path('subjects/create/', views.create_subject_view, name='subject-create-template'),
    path('subjects/<int:pk>/update/', views.update_subject_view, name='subject-update-template'),
    path('subjects/<int:pk>/delete/', views.delete_subject_view, name='subject-delete-template'),

    # Unit URLs (for templates)
    path('units/', views.list_units_view, name='unit-list-template'),
    path('units/create/', views.create_unit_view, name='unit-create-template'),
    path('units/<int:pk>/update/', views.update_unit_view, name='unit-update-template'),
    path('units/<int:pk>/delete/', views.delete_unit_view, name='unit-delete-template'),

    # API Views
    path('offer-management/', views.OfferManagement, name='offer-management'),  # Use as_view() here
    # API Views
    path('api/offers/create/', OfferCreateAPIView.as_view(), name='offer-create-api'),
    path('api/offers/<int:pk>/update/', OfferUpdateAPIView.as_view(), name='offer-update-api'),
    path('api/offers/<int:pk>/delete/', OfferDeleteAPIView.as_view(), name='offer-delete-api'),

    path('mocktest/', MockTestListView.as_view(), name='mocktest-list'),
    path('mocktest_user/', views.MockTest_user, name='mocktest-user'),
    path('mock-test/<int:mocktest_id>/', mocktest_detailview, name='mocktest_question_detail'),
    #path('mock-test/<int:pk>/', views.MockTestDetailView.as_view(), name='mock_test_detail'),
    #path('mock-test/<int:pk>/start/', views.mocktest_view, name='start_mock_test'),
    path('mock-test/<int:mocktest_id>/submit/', test_submit, name='mocktest_submit'),
    #path('mocktest/<int:pk>/load-questions/<int:subject_id>/', LoadQuestionsBySubject.as_view(), name='load-questions-by-subject'),
    path('mocktest/new/', MockTestCreateView.as_view(), name='mocktest-create'),
    path('mocktest/<int:pk>/update/', MockTestUpdateView.as_view(), name='mocktest-update'),
    path('mocktest/<int:pk>/delete/', MockTestDeleteView.as_view(), name='mocktest-delete'),

]

# Serve media files during development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

