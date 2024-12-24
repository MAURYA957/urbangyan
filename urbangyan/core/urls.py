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
    dashboard_view, logout, UserSessionListCreateAPIView, UserSessionDetailAPIView,
    topic_user, SubjectViewSet, UnitViewSet, OfferCreateAPIView, OfferUpdateAPIView,
    OfferDeleteAPIView, OfferManagement, get_units, MockTestViewSet, MockTestListView,
    MockTestCreateView, MockTestUpdateView, MockTestDeleteView, MockTest_user, test_submit,
    mocktest_detailview, test_result, register_user, user_quizzes_view, quizzes_by_subject, AdvertisementViewSet,
    JobTypeViewSet, JobCategoryViewSet, JobStageViewSet, JobViewSet, SavedJobViewSet, ExperienceLevelViewSet,
    CartViewSet, OrderViewSet
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
router.register(r'advertisements', AdvertisementViewSet)
router.register(r'job-types', JobTypeViewSet)
router.register(r'job-categories', JobCategoryViewSet)
router.register(r'job-stages', JobStageViewSet)
router.register(r'jobs', JobViewSet)
router.register(r'saved-jobs', SavedJobViewSet)
router.register(r'experience-level', ExperienceLevelViewSet)
router.register(r'cart', CartViewSet)
router.register(r'order', OrderViewSet)

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
    #path('blogs/<int:blog_pk>/comment/<int:comment_pk>/reply/', views.reply_comment, name='reply-comment'),

    # User management URLs
    path('create_user/', register_user, name='create_user'),
    path('update_user/', TemplateView.as_view(template_name='update_user.html'), name='update_user'),
    path('delete_user/', TemplateView.as_view(template_name='delete_user.html'), name='delete_user'),

    # Questions URLs
    path('questions/', views.list_questions_view, name='questions-list-template'),
    path('questions/create/', views.create_question_view, name='question-create-template'),
    path('questions/<int:pk>/update/', views.update_question_view, name='question-update-template'),
    path('questions/<int:pk>/delete/', views.delete_question_view, name='question-delete-template'),
    #path('questions_view/', views.list_questions_view, name='questions-list-template'),

    # quiz list and detail views
    path('questions_view/<int:quiz_id>/', views.questions_view, name='questions_view'),
    # View to display the quiz and questions
    path('questions_view/<int:quiz_id>/submit/', views.questions_submit, name='questions_submit'),
    # URL to handle quiz submission

    # URL to save result (if you have result-saving logic)
    path('questions_view/<int:quiz_id>/save-result/', views.questions_submit, name='save-questions-result'),


    #Quize template url
    path('quizzes/', views.list_quizzes_view, name='quiz-list-template'),
    path('quizzes/create/', views.create_quiz_view, name='quiz-create-template'),
    path('quizzes/<int:pk>/update/', views.update_quiz_view, name='quiz-update-template'),
    path('quizzes/<int:pk>/delete/', views.delete_quiz_view, name='quiz-delete-template'),
    path('quizzes/<int:subject_id>/', quizzes_by_subject, name='quizzes_by_subject'),
    path('quiz_view/', user_quizzes_view, name='quiz_view'),


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
    path('subjects_user/', views.subject_list, name='subject-list'),
    path('subjects/<int:pk>/', views.subject_detail, name='subject-detail'),

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

    # MockTest views
    path('mocktest/', MockTestListView.as_view(), name='mocktest-list'),
    path('mocktest/new/', MockTestCreateView.as_view(), name='mocktest-create'),
    path('mocktest/<int:pk>/update/', MockTestUpdateView.as_view(), name='mocktest-update'),
    path('mocktest/<int:pk>/delete/', MockTestDeleteView.as_view(), name='mocktest-delete'),

    # User-specific MockTest views
    path('mocktest_user/', MockTest_user, name='mocktest-user'),
    path('mocktest/<int:mocktest_id>/instructions/', views.instructions_view, name='mocktest_instructions'),
    path('mock-test/<int:mocktest_id>/questions/', mocktest_detailview, name='mocktest_question_detail'),

    # Submission and results
    path('mock-test/<int:mocktest_id>/submit/', test_submit, name='mocktest_submit'),
    path('mock-test/<int:mocktest_id>/result/<uuid:submission_uuid>/', views.test_result, name='mocktest_result'),

    #News
    path('news/', views.CurrentAffaires, name='news'),

    #Jobs link
    path('sarkari-jobs/', views.sarkari_jobs, name='sarkari_jobs'),
    path('private-jobs/', views.private_jobs, name='private_jobs'),

    # Add to cart: item_type can be 'course' or 'test'
    path('add-to-cart/<str:item_type>/<int:item_id>/', views.add_to_cart, name='add_to_cart'),

    # View cart
    path('cart/', views.view_cart, name='view_cart'),

    # Proceed to checkout
    path('checkout/', views.checkout, name='checkout'),
    path('payment/<int:order_id>/', views.payment, name='payment'),
    path('payment-success/<int:order_id>/', views.payment_success, name='payment_success'),

]

# Serve media files during development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


