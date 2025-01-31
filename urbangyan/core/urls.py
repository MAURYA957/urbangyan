from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views
from .views import (
    BlogViewSet,
    CourseViewSet,
    TopicViewSet,
    UserRegistrationView,
    UserUpdateView,
    CustomTokenObtainPairView,
    QuestionsViewSet, login,
    LoginAPIView,
    dashboard_view, logout, UserSessionListCreateAPIView, UserSessionDetailAPIView,
    topic_user, SubjectViewSet, UnitViewSet, OfferCreateAPIView, OfferUpdateAPIView,
    OfferDeleteAPIView, OfferManagement, get_units, MockTestViewSet, MockTestListView,
    MockTestCreateView, MockTestUpdateView, MockTestDeleteView, MockTest_user, test_submit,
    mocktest_detailview, register_user, AdvertisementViewSet,
    JobTypeViewSet, JobCategoryViewSet, JobStageViewSet, JobViewSet, SavedJobViewSet, ExperienceLevelViewSet,
    CartViewSet, OrderViewSet, CurrentAffairAPIView, current_affairs_list, AffairsCategoryViewSet, job_detail_view,
    update_user_view, delete_user_view, submit_quiz, upload_questions, upload_questions_view
)
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.conf import settings
from django.conf.urls.static import static
from django.contrib.auth import views as auth_views
from django.conf.urls.i18n import i18n_patterns



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
router.register(r'affairs-categories', AffairsCategoryViewSet)

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
    path('user/<int:pk>/update/', update_user_view, name='update_user'),
    path('user/<int:pk>/delete/', delete_user_view, name='delete_user'),
    path('user_dashboard/', views.user_dashboard, name='user_dashboard'),
    # Password reset URLs
    path('password-reset/', auth_views.PasswordResetView.as_view(template_name='user/password_reset.html'), name='password_reset'),
    path('password-reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='user/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='user/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='user/password_reset_complete.html'), name='password_reset_complete'),

    # Questions URLs
    path('questions/', views.list_questions_view, name='questions-list-template'),
    path('questions/create/', views.create_question_view, name='question-create-template'),
    path('questions/<int:pk>/update/', views.update_question_view, name='question-update-template'),
    path('questions/<int:pk>/delete/', views.delete_question_view, name='question-delete-template'),
    path('filter-units/', views.filter_units, name='filter_units'),
    path('filter-topics/', views.filter_topics, name='filter_topics'),

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
    path('sarkari-jobs/<int:pk>/', job_detail_view, name='job_detail'),

    # Add to cart: item_type can be 'course' or 'test'
    path('add-to-cart/<str:item_type>/<int:item_id>/', views.add_to_cart, name='add_to_cart'),

    # View cart
    path('cart/', views.view_cart, name='view_cart'),

    # Proceed to checkout
    path('checkout/', views.checkout, name='checkout'),
    path('payment/<int:order_id>/', views.payment, name='payment'),
    path('payment-success/<int:order_id>/', views.payment_success, name='payment_success'),

    # Combined endpoint for all actions
    path('current-affairs/', CurrentAffairAPIView.as_view(), name='current_affairs_list_create'),
    path('current-affairs/<int:pk>/', CurrentAffairAPIView.as_view(), name='current_affairs_detail'),
    path('current-affairs-list/', current_affairs_list, name='current_affairs_list'),

    # URL for creating a quiz based on subject, unit, or topic
    path('create_quiz/', views.quiz, name='create_quiz'),
    path('submit-quiz/', submit_quiz, name='submit_quiz'),
    path('upload-questions/', upload_questions, name='upload_questions'),
    path('upload_questions_template/', upload_questions_view, name='upload_questions_template'),
]

# Serve media files during development
urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)


