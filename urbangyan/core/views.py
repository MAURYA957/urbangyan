from django.contrib import messages
from django.contrib.admin import action
from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET
from rest_framework import viewsets, generics
from django.contrib.auth.models import User
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.utils import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import re
from django.contrib.auth.decorators import login_required
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken
from .models import Blog, Course, Topic, Quiz, Questions, User, QuizResult, QuizName, UserSession, Comment, Subject, \
    Unit, Offer, MockTest, MockTestSubjectConfig, UserResponse, Badge
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from .models import Course, Subject

import logging
from .serializers import (
    BlogSerializer,
    CourseSerializer,
    TopicSerializer,
    QuizSerializer,
    QuestionsSerializer,
    UserSerializer,
    CustomTokenObtainPairSerializer, UserSessionSerializer, SubjectSerializer, UnitSerializer, OfferSerializer,
    MockTestSerializer
)

# Initialize the logger
logger = logging.getLogger(__name__)
User = get_user_model()


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class UserUpdateView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer


class BlogViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        blogs = Blog.objects.all()
        serializer = BlogSerializer(blogs, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        blog = get_object_or_404(Blog, pk=pk)
        serializer = BlogSerializer(blog)
        return Response(serializer.data)

    def create(self, request):
        serializer = BlogSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(author=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        blog = get_object_or_404(Blog, pk=pk)
        serializer = BlogSerializer(blog, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        blog = get_object_or_404(Blog, pk=pk)
        blog.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class QuizViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        quizzes = Quiz.objects.all()
        serializer = QuizSerializer(quizzes, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        quiz = get_object_or_404(Quiz, pk=pk)
        serializer = QuizSerializer(quiz)
        return Response(serializer.data)

    def create(self, request):
        serializer = QuizSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        quiz = get_object_or_404(Quiz, pk=pk)
        serializer = QuizSerializer(quiz, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        quiz = get_object_or_404(Quiz, pk=pk)
        quiz.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class QuestionsViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        questions = Questions.objects.all()
        serializer = QuestionsSerializer(questions, many=True)
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        question = get_object_or_404(Questions, pk=pk)
        serializer = QuestionsSerializer(question)
        return Response(serializer.data)

    def create(self, request):
        serializer = QuestionsSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        question = get_object_or_404(Questions, pk=pk)
        serializer = QuestionsSerializer(question, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        question = get_object_or_404(Questions, pk=pk)
        question.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]  # Set default permission class

    def list(self, request):
        logger.debug("Listing all users")
        users = User.objects.all()
        serializer = UserSerializer(users, many=True)
        logger.debug(f"Users retrieved: {serializer.data}")
        return Response(serializer.data)

    def retrieve(self, request, pk=None):
        logger.debug(f"Retrieving user with ID: {pk}")
        user = get_object_or_404(User, pk=pk)
        serializer = UserSerializer(user)
        logger.debug(f"User details: {serializer.data}")
        return Response(serializer.data)

    def create(self, request):
        logger.debug("Creating a new user with data: %s", request.data)
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            logger.info(f"User created successfully: {user.id}")

            # Handle many-to-many fields after saving the user instance
            if 'groups' in request.data:
                user.groups.set(request.data['groups'])
                logger.debug(f"Groups set for user {user.id}: {request.data['groups']}")
            if 'user_permissions' in request.data:
                user.user_permissions.set(request.data['user_permissions'])
                logger.debug(f"User permissions set for user {user.id}: {request.data['user_permissions']}")

            # Generate JWT token for the new user
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            logger.info(f"Generated tokens for user {user.id}")

            return Response({
                'user': serializer.data,
                'access': access_token,
                'refresh': str(refresh)
            }, status=status.HTTP_201_CREATED)

        # Log the validation errors
        logger.error(f"Validation errors: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, pk=None):
        logger.debug(f"Updating user with ID: {pk} with data: {request.data}")
        user = get_object_or_404(User, pk=pk)
        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            user = serializer.save()
            logger.info(f"User updated successfully: {user.id}")

            # Handle many-to-many fields
            if 'groups' in request.data:
                user.groups.set(request.data['groups'])
                logger.debug(f"Groups updated for user {user.id}: {request.data['groups']}")
            if 'user_permissions' in request.data:
                user.user_permissions.set(request.data['user_permissions'])
                logger.debug(f"User permissions updated for user {user.id}: {request.data['user_permissions']}")

            return Response(serializer.data)

        logger.error(f"Validation errors on update: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        logger.debug(f"Deleting user with ID: {pk}")
        user = get_object_or_404(User, pk=pk)
        user.delete()
        logger.info(f"User deleted successfully: {pk}")
        return Response(status=status.HTTP_204_NO_CONTENT)


logger = logging.getLogger(__name__)


class UsernameAvailabilityView(APIView):
    permission_classes = [AllowAny]  # Allows unauthenticated users

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'username',  # name of the parameter
                openapi.IN_QUERY,  # where the parameter is
                description="The username to check for availability.",
                type=openapi.TYPE_STRING,  # type of the parameter
                required=True,  # if the parameter is required
            )
        ],
        responses={
            200: openapi.Response('Success', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'available': openapi.Schema(type=openapi.TYPE_BOOLEAN)
                }
            )),
            400: openapi.Response('Bad Request', openapi.Schema(
                type=openapi.TYPE_OBJECT,
                properties={
                    'detail': openapi.Schema(type=openapi.TYPE_STRING)
                }
            ))
        }
    )
    def get(self, request):
        logger.info(f"Incoming request: {request.GET}")
        username = request.GET.get('username', None)

        # Validate username format (example: alphanumeric, 3-30 characters)
        if username:
            if not re.match(r'^[a-zA-Z0-9]{3,30}$', username):
                return Response({'detail': 'Username must be alphanumeric and between 3 to 30 characters long.'},
                                status=status.HTTP_400_BAD_REQUEST)

            available = not User.objects.filter(username=username).exists()
            return Response({'available': available})

        return Response({'detail': 'Username parameter is required.'},
                        status=status.HTTP_400_BAD_REQUEST)


class UserSessionListCreateAPIView(generics.ListCreateAPIView):
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        """Override the create method to set the user from the request."""
        serializer.save(user=self.request.user, session_key=self.request.session.session_key)


class UserSessionDetailAPIView(generics.RetrieveUpdateDestroyAPIView):
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]

    def perform_update(self, serializer):
        """Override the update method to set the last_accessed time."""
        serializer.save(last_accessed=self.request.user_session.last_accessed)

    def perform_destroy(self, instance):
        """Override the destroy method for additional logging or cleanup if necessary."""
        # You can log the deletion or perform other cleanup actions here
        instance.delete()


def list_quizzes_view(request):
    quizzes = Quiz.objects.all()
    return render(request, 'quiz_list.html', {'quizzes': quizzes})


def user_quizzes_view(request):
    quizzes = Quiz.objects.all()
    return render(request, 'quiz_view.html', {'quizzes': quizzes})


@login_required
def create_quiz_view(request):
    courses = Course.objects.all()

    if request.method == 'POST':
        quizname = request.POST.get('quizname')
        description = request.POST.get('description')
        course_id = request.POST.get('course')  # ForeignKey field
        course = get_object_or_404(Course, pk=course_id)
        image = request.FILES.get('image')

        # Create the Quiz object
        Quiz.objects.create(
            quiz=quizname,
            description=description,
            course=course,
            image=image
        )

        # Add success message
        messages.success(request, 'Quiz created successfully!')

        # Redirect after successful creation
        return redirect(reverse('user_quizzes_view'))

    return render(request, 'create_quiz.html', {'courses': courses})


@login_required
def update_quiz_view(request, pk):
    quiz = get_object_or_404(Quiz, pk=pk)
    courses = Course.objects.all()

    if request.method == 'POST':
        quizname = request.POST.get('quizname')
        description = request.POST.get('description')
        course_id = request.POST.get('course')
        course = get_object_or_404(Course, pk=course_id)

        if 'image' in request.FILES:
            quiz.image = request.FILES['image']  # Update the image if a new one is uploaded

        quiz.quiz = quizname
        quiz.description = description
        quiz.course = course
        quiz.save()

        # Add success message
        messages.success(request, 'Quiz updated successfully!')

        # Redirect after successful update
        return redirect(reverse('quiz-list-template'))

    return render(request, 'update_quiz.html', {'quiz': quiz, 'courses': courses})


@login_required
def delete_quiz_view(request, pk):
    quiz = get_object_or_404(Quiz, pk=pk)
    if request.method == 'POST':
        quiz.delete()
        return redirect(reverse('quiz-list-template'))
    return render(request, 'delete_quiz.html', {'quiz': quiz})


# Assuming you're using a custom User model
from django.contrib.auth import get_user_model

User = get_user_model()


class CourseViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows courses to be created, retrieved, updated, or deleted.
    The staff user creating the course is assigned automatically.
    """
    permission_classes = [AllowAny]
    queryset = Course.objects.all()
    serializer_class = CourseSerializer

    def perform_create(self, serializer):
        """
        Overriding perform_create to set the staff user as the current user.
        """
        serializer.save(staff=self.request.user)

    def perform_update(self, serializer):
        """
        Overriding perform_update to ensure the user can only update if they are staff/admin.
        """
        serializer.save(staff=self.request.user)

    def destroy(self, request, *args, **kwargs):
        """
        Custom delete behavior to ensure only the staff/admin can delete their courses.
        """
        course = self.get_object()
        if request.user == course.staff or request.user.is_staff:
            return super().destroy(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to delete this course."},
                        status=status.HTTP_403_FORBIDDEN)


class TopicViewSet(viewsets.ModelViewSet):
    """
    API endpoint that allows topics to be created, retrieved, updated, or deleted.
    The staff user creating the topic is assigned automatically.
    """
    permission_classes = [IsAuthenticated]
    queryset = Topic.objects.all()
    serializer_class = TopicSerializer

    def perform_create(self, serializer):
        """
        Overriding perform_create to set the staff user as the current user.
        """
        serializer.save(staff=self.request.user)

    def perform_update(self, serializer):
        """
        Overriding perform_update to ensure the user can only update if they are staff/admin.
        """
        serializer.save(staff=self.request.user)

    def destroy(self, request, *args, **kwargs):
        """
        Custom delete behavior to ensure only the staff/admin can delete their topics.
        """
        topic = self.get_object()
        if request.user == topic.staff or request.user.is_staff:
            return super().destroy(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to delete this topic."},
                        status=status.HTTP_403_FORBIDDEN)


"""
@login_required
def course_management_view(request, pk=None):
    try:
        if pk:  # If pk is provided, we're updating or deleting
            course = get_object_or_404(Course, pk=pk)

            # Check permissions
            if request.user != course.staff and not request.user.is_staff:
                messages.error(request, 'You do not have permission to modify this course.')
                return redirect(reverse('course-list-template'))

            if request.method == 'POST':
                if 'delete' in request.POST:  # Handle delete
                    logger.info("User %s deleting course: %s", request.user.username, course.title)
                    course.delete()
                    messages.success(request, 'Course deleted successfully!')
                    return redirect(reverse('course-list-template'))

                # Handle update
                logger.info("User %s updating course: %s", request.user.username, course.title)
                course.title = request.POST.get('title')
                course.description = request.POST.get('description')
                course.image = request.FILES.get('image', course.image)  # Keep old image if none provided
                course.price = request.POST.get('price')
                subjects_ids = request.POST.getlist('subjects')
                course.subjects.set(subjects_ids)
                course.save()
                messages.success(request, 'Course updated successfully!')
                return redirect(reverse('course-list-template'))

        else:  # Creating a new course
            if request.method == 'POST':
                logger.info("Course creation started by user: %s", request.user.username)
                title = request.POST.get('title')
                description = request.POST.get('description')
                image = request.FILES.get('image')
                price = request.POST.get('price')
                subjects_ids = request.POST.getlist('subjects')

                logger.debug(f"Form data retrieved - Title: {title}, Price: {price}, Subjects: {subjects_ids}")

                course = Course.objects.create(
                    title=title,
                    description=description,
                    image=image,
                    price=price,
                    staff=request.user
                )
                course.subjects.set(subjects_ids)
                logger.info("Course created: %s", course.title)
                messages.success(request, 'Course created successfully!')
                return redirect(reverse('course-user-template'))

        # Render form for both create and update
        subjects = Subject.objects.all()
        context = {
            'course': course if pk else None,
            'subjects': subjects,
            'is_update': pk is not None  # Flag to check if we're in update mode
        }
        return render(request, 'course_management.html', context)

    except Exception as e:
        logger.error("Error during course management: %s", str(e))
        messages.error(request, 'An error occurred while processing your request.')
        return redirect(reverse('blogs-list-template'))


"""


@login_required
def create_course_view(request):
    try:
        if request.method == 'POST':
            # Step 1: Log the start of the course creation
            logger.info("Course creation started by user: %s", request.user.username)

            # Step 2: Retrieve form data
            title = request.POST.get('title')
            description = request.POST.get('description')
            image = request.FILES.get('image')
            price = request.POST.get('price')
            subjects_ids = request.POST.getlist('subjects')

            logger.debug(f"Form data retrieved - Title: {title}, Price: {price}, Subjects: {subjects_ids}")

            # Step 3: Create the Course object without subjects or staff directly
            course = Course.objects.create(
                title=title,
                description=description,
                image=image,
                price=price,
                Staff=request.user.username  # Assign the current user as staff
            )
            logger.info("Course created: %s", course.title)

            # Step 4: Associate selected subjects with the course
            course.subjects.set(subjects_ids)
            course.save()

            logger.info("Subjects associated with course: %s", subjects_ids)

            # Step 5: Success message and redirect
            messages.success(request, 'Course created successfully!')
            logger.info("Success message displayed, redirecting to course list.")

            return redirect(reverse('course-user-template'))

        # Step 6: Render the form if GET request
        subjects = Subject.objects.all()
        logger.info("Course creation form rendered.")
        return render(request, 'create_course.html', {'subjects': subjects})

    except Exception as e:
        # Step 7: Handle any errors and log them
        logger.error("Error during course creation: %s", str(e))
        messages.error(request, 'An error occurred while creating the course.')
        return redirect(reverse('create_course.html'))

    except Exception as e:
        # Step 7: Handle any errors and log them
        logger.error("Error during course creation: %s", str(e))
        messages.error(request, 'An error occurred while creating the course.')
        return redirect(reverse('course-list-template'))


@login_required
def update_course_view(request, pk):
    try:
        course = get_object_or_404(Course, pk=pk)

        # Step 1: Check permissions
        if request.user.username != course.Staff and not request.user.is_staff:
            messages.error(request, 'You do not have permission to update this course.')
            logger.warning("User %s attempted to update course without permission.", request.user.username)
            return redirect(reverse('course-list-template'))

        # Step 2: Handle POST request (updating course)
        if request.method == 'POST':
            logger.info("User %s updating course: %s", request.user.username, course.title)

            # Update course fields
            course.title = request.POST.get('title')
            course.description = request.POST.get('description')
            course.image = request.FILES.get('image', course.image)  # Keep old image if none provided
            course.price = request.POST.get('price')

            # Updating the subjects (many-to-many field)
            subjects_ids = request.POST.getlist('subjects')
            course.subjects.set(subjects_ids)

            course.save()
            logger.info("Course updated: %s", course.title)

            messages.success(request, 'Course updated successfully!')
            return redirect(reverse('course-list-template'))

        # Step 3: Render form for GET request
        subjects = Subject.objects.all()
        logger.info("Rendering course update form for course: %s", course.title)
        return render(request, 'update_course.html', {'course': course, 'subjects': subjects})

    except Exception as e:
        logger.error("Error updating course: %s", str(e))
        messages.error(request, 'An error occurred while updating the course.')
        return redirect(reverse('course-list-template'))


@login_required
def delete_course_view(request, pk):
    try:
        course = get_object_or_404(Course, pk=pk)

        # Step 1: Check permissions
        if request.user.username != course.Staff and not request.user.is_staff:
            messages.error(request, 'You do not have permission to delete this course.')
            logger.warning("User %s attempted to delete course without permission.", request.user.username)
            return redirect(reverse('course-list-template'))

        # Step 2: Handle POST request (deleting course)
        if request.method == 'POST':
            logger.info("User %s deleting course: %s", request.user.username, course.title)
            course.delete()
            logger.info("Course deleted: %s", course.title)
            messages.success(request, 'Course deleted successfully!')
            return redirect(reverse('course-list-template'))

        # Step 3: Render confirmation page for GET request
        logger.info("Rendering delete confirmation for course: %s", course.title)
        return render(request, 'delete_course.html', {'course': course})

    except Exception as e:
        logger.error("Error deleting course: %s", str(e))
        messages.error(request, 'An error occurred while deleting the course.')
        return redirect(reverse('course-list-template'))


# ViewSet for Topic
class TopicViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Topic.objects.all()
    serializer_class = TopicSerializer

    def perform_create(self, serializer):
        # Automatically set the staff user as the current user for create
        serializer.save(staff=self.request.user)

    def perform_update(self, serializer):
        # Automatically set the staff user as the current user for update
        serializer.save(staff=self.request.user)

    def destroy(self, request, *args, **kwargs):
        topic = self.get_object()
        if request.user == topic.staff or request.user.is_staff:
            return super().destroy(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to delete this topic."},
                        status=status.HTTP_403_FORBIDDEN)


# ViewSet for Unit
class UnitViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Unit.objects.all()
    serializer_class = UnitSerializer

    def perform_create(self, serializer):
        # Automatically set the staff user as the current user for create
        serializer.save(staff=self.request.user)

    def perform_update(self, serializer):
        # Automatically set the staff user as the current user for update
        serializer.save(staff=self.request.user)

    def destroy(self, request, *args, **kwargs):
        unit = self.get_object()
        if request.user == unit.staff or request.user.is_staff:
            return super().destroy(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to delete this unit."}, status=status.HTTP_403_FORBIDDEN)


# ViewSet for Subject
class SubjectViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]
    queryset = Subject.objects.all()
    serializer_class = SubjectSerializer

    def perform_create(self, serializer):
        # Automatically set the staff user as the current user for create
        serializer.save(staff=self.request.user)

    def perform_update(self, serializer):
        # Automatically set the staff user as the current user for update
        serializer.save(staff=self.request.user)

    def destroy(self, request, *args, **kwargs):
        subject = self.get_object()
        if request.user == subject.staff or request.user.is_staff:
            return super().destroy(request, *args, **kwargs)
        return Response({"detail": "You do not have permission to delete this subject."},
                        status=status.HTTP_403_FORBIDDEN)


# to be checked followings
def course_user(request):
    courses = Course.objects.all()
    return render(request, 'course_user.html', {'courses': courses})


def list_courses_view(request):
    courses = Course.objects.all()
    return render(request, 'course_list.html', {'courses': courses})


def list_topics_view(request):
    topics = Topic.objects.all()
    return render(request, 'list_topics_view.html', {'topics': topics})


def list_subjects_view(request):
    subjects = Subject.objects.all()
    return render(request, 'subject/list_subjects_view.html', {'subjects': subjects})


def list_units_view(request):
    units = Unit.object.all()
    return render(request, 'unit/list_units_view.html', {'units': units})


@login_required
def list_questions_view(request):
    questions = Questions.objects.all()
    return render(request, 'questions_list.html', {'questions': questions})


def quizname_user(request, quiz_id):
    quiz = get_object_or_404(Quiz, id=quiz_id)  # Fetch the quiz object or return 404 if not found
    quiznames = QuizName.objects.filter(quiz=quiz)  # Filter QuizName objects by the fetched quiz
    return render(request, 'quizname_user.html',
                  {'quiznames': quiznames})  # Pass filtered QuizName objects to the template


@login_required
def quiznamelist(request):
    quiznames = QuizName.objects.all()  # Changed variable name to plural for clarity
    return render(request, 'quiznamelist.html', {'quiznames': quiznames})  # Updated context variable to plural


@require_GET
def get_quiznames(request):
    quiz_id = request.GET.get('quiz_id')
    quiznames = QuizName.objects.filter(quiz_id=quiz_id).values('id', 'quizname')
    quiznames_list = list(quiznames)  # Convert to a list of dictionaries
    return JsonResponse(quiznames_list, safe=False)


@login_required
def create_quizename_view(request):
    if request.method == 'POST':
        quizname_text = request.POST.get('quizname')  # Get the quiz name from the POST request
        quiz_id = request.POST.get('quiz')  # Get the selected quiz ID from the POST request

        quiz = get_object_or_404(Quiz, pk=quiz_id)  # Use Quiz model here

        # Create a new QuizName instance
        QuizName.objects.create(
            quiz=quiz,  # Use the Quiz instance
            quizname=quizname_text,  # Assign the quiz name
        )
        return redirect(reverse('quizlistview'))  # Redirect to the quiz name list view

    quizzes = Quiz.objects.all()  # Get all quizzes for selection
    return render(request, 'create_quizname.html', {'quizzes': quizzes})  # Pass quizzes to the template


@login_required
def update_quizname(request, pk):
    quizname = get_object_or_404(QuizName, pk=pk)
    quiz = Quiz.objects.filter(quiz=quizname.quiz).all()  # Adjust to reference the quiz associated with the quizname

    if request.method == 'POST':
        quizname.quizname = request.POST.get('quizname')  # Correct reference to the quizname object
        for q in quiz:  # Loop through all quizzes related to this quizname
            q.quiz = request.POST.get('quiz')  # Ensure you correctly update the quiz
            q.save()  # Save each quiz object
        quizname.save()  # Save the quizname object
        return redirect(reverse('quizlistview'))

    return render(request, 'update_quizname.html',
                  {'quizname': quizname, 'quizzes': quiz})  # Pass quizzes to the template


@login_required
def delete_quizname(request, pk):
    quizname = get_object_or_404(QuizName, pk=pk)

    if request.method == 'POST':
        quizname.delete()
        return redirect(reverse('quizlistview'))

    return render(request, 'delete_quizname.html', {'quizname': quizname})


import logging
from django.contrib.auth.decorators import login_required
from .models import Questions, Quiz, QuizName, Subject

# Set up logging
logger = logging.getLogger(__name__)


@login_required
def create_question_view(request):
    if request.method == 'POST':
        try:
            quiz_id = request.POST.get('quiz')  # Get the selected quiz ID from the POST request
            quizname_id = request.POST.get('quizname')  # Get the selected quiz name ID from the POST request
            subject_id = request.POST.get('subject')  # Get the selected subject ID from the POST request
            question_level = request.POST.get('question_level')  # Get the selected question level from the POST request

            quiz = get_object_or_404(Quiz, pk=quiz_id)  # Get the selected Quiz instance
            quizname = get_object_or_404(QuizName, pk=quizname_id)  # Get the selected QuizName instance
            subject = get_object_or_404(Subject, pk=subject_id)  # Get the selected Subject instance

            question = request.POST.get('question')
            option_1 = request.POST.get('option_1')
            option_2 = request.POST.get('option_2')
            option_3 = request.POST.get('option_3')
            option_4 = request.POST.get('option_4')
            answer = request.POST.get('answer')
            explanation = request.POST.get('explanation')

            # Create the question
            Questions.objects.create(
                quizname=quizname,
                quiz=quiz,
                Subject=subject,
                question_level=question_level,
                question=question,
                option_1=option_1,
                option_2=option_2,
                option_3=option_3,
                option_4=option_4,
                answer=answer,
                explanation=explanation,
            )

            # Log success
            logger.info("Question created successfully: %s", question)
            messages.success(request, "Question created successfully!")

            return redirect(reverse('questions-list-template'))

        except Exception as e:
            logger.error("Error creating question: %s", str(e))
            messages.error(request, "An error occurred while creating the question.")

    # Fetch all quizzes, quiz names, and subjects for the dropdowns
    quizzes = Quiz.objects.all()
    quiznames = QuizName.objects.all()
    subjects = Subject.objects.all()

    return render(request, 'create_question.html', {
        'quizzes': quizzes,
        'quiznames': quiznames,
        'subjects': subjects,
    })


@login_required
def update_question_view(request, pk):
    question = get_object_or_404(Questions, pk=pk)
    quiznames = QuizName.objects.filter(quiz=question.quiz).all()  # Get quiz names associated with the quiz
    subjects = Subject.objects.all()  # Fetch all subjects for the dropdown

    if request.method == 'POST':
        # Use the selected quizname and subject from the POST request
        question.quizname = get_object_or_404(QuizName, pk=request.POST.get('quizname'))
        question.Subject = get_object_or_404(Subject, pk=request.POST.get('subject'))  # New subject field
        question.question = request.POST.get('question')
        question.option_1 = request.POST.get('option_1')
        question.option_2 = request.POST.get('option_2')
        question.option_3 = request.POST.get('option_3')
        question.option_4 = request.POST.get('option_4')
        question.answer = request.POST.get('answer')
        question.explanation = request.POST.get('explanation')
        question.question_level = request.POST.get('question_level')  # New question level field

        question.save()

        # Add a success message
        messages.success(request, "Question updated successfully!")

        return redirect(reverse('questions-list-template'))

    return render(request, 'update_question.html', {
        'question': question,
        'quiznames': quiznames,
        'subjects': subjects,  # Pass subjects to the template for the dropdown
    })


@login_required
def delete_question_view(request, pk):
    question = get_object_or_404(Questions, pk=pk)

    if request.method == 'POST':
        question.delete()
        messages.success(request, "Question deleted successfully!")  # Add success message
        return redirect(reverse('questions-list-template'))

    return render(request, 'delete_question.html', {'question': question})


def get_units(request, subject_id):
    try:
        units = Unit.objects.filter(subject_id=subject_id)  # Adjust filter according to your models
        unit_data = [{'id': unit.pk, 'name': unit.name} for unit in units]
        return JsonResponse({'units': unit_data})
    except Exception as e:
        # Handle potential errors, like logging
        return JsonResponse({'error': str(e)}, status=500)


import logging
from django.contrib import messages
from django.shortcuts import redirect
from django.contrib.auth.decorators import login_required
from .models import Topic, Course, Unit  # Ensure all necessary imports are present

# Set up a logger
logger = logging.getLogger(__name__)


@login_required
def create_topic_view(request):
    if request.method == 'POST':
        topic_name = request.POST.get('topic')
        description = request.POST.get('description')
        image = request.FILES.get('image')
        course_id = request.POST.get('course')  # Get the selected course ID
        subject_id = request.POST.get('subject')  # Get the selected subject ID
        unit_id = request.POST.get('unit')  # Get the selected unit ID

        # Get the Course object; this will raise a 404 error if not found
        course = get_object_or_404(Course, pk=course_id)

        # Get the Subject and Unit objects; these will raise a 404 error if not found
        subject = get_object_or_404(Subject, pk=subject_id) if subject_id else None
        unit = get_object_or_404(Unit, pk=unit_id) if unit_id else None

        try:
            # Create a new Topic instance
            Topic.objects.create(
                topic=topic_name,
                description=description,
                image=image,
                staff=request.user,  # Set the staff as the current user
                course=course,
                subject=subject,  # Associate the subject if provided
                unit=unit  # Associate the unit if provided
            )
            # Log a success message
            logger.info(f"Topic '{topic_name}' created successfully by {request.user.username}.")
            messages.success(request, "Topic created successfully.")
            return redirect(reverse('topic-list-template'))
        except Exception as e:
            # Log the error
            logger.error(f"Error creating topic '{topic_name}': {str(e)}")
            messages.error(request, "There was an error creating the topic. Please try again.")

    # Pass courses, subjects, and units for selection in the form
    courses = Course.objects.all()
    subjects = Subject.objects.all()  # Retrieve all subjects for selection
    units = Unit.objects.all()  # Retrieve all units for selection

    return render(request, 'create_topic.html', {
        'courses': courses,
        'subjects': subjects,
        'units': units
    })


# Set up a logger
logger = logging.getLogger(__name__)


@login_required
def update_topic_view(request, pk):
    topic = get_object_or_404(Topic, pk=pk)

    # Check for permission
    if request.user != topic.staff and not request.user.is_staff:
        messages.error(request, 'You do not have permission to update this topic.')
        return redirect(reverse('topic-list-template'))

    if request.method == 'POST':
        topic.topic = request.POST.get('topic')
        topic.description = request.POST.get('description')
        new_image = request.FILES.get('image')

        # Keep the old image if no new one is provided
        if new_image:
            topic.image = new_image

        topic.save()

        messages.success(request, "Topic updated successfully.")
        return redirect(reverse('topic-list-template'))

    return render(request, 'update_topic.html', {'topic': topic})


# Delete Topic
@login_required
def delete_topic_view(request, pk):
    topic = get_object_or_404(Topic, pk=pk)

    # Check for permission
    if request.user != topic.staff and not request.user.is_staff:
        messages.error(request, 'You do not have permission to delete this topic.')
        return redirect(reverse('topic-list-template'))

    if request.method == 'POST':
        topic.delete()
        messages.success(request, "Topic deleted successfully.")
        return redirect(reverse('topic-list-template'))

    return render(request, 'delete_topic.html', {'topic': topic})


# Similar logic for Unit and Subject follows the same pattern:

# Create Unit
@login_required
def create_unit_view(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        image = request.FILES.get('image')

        Unit.objects.create(
            title=title,
            description=description,
            image=image,
            staff=request.user  # Set the staff as the current user
        )
        return redirect(reverse('unit-list-template'))

    return render(request, 'unit/create_unit.html')


# Update Unit
@login_required
def update_unit_view(request, pk):
    unit = get_object_or_404(Unit, pk=pk)
    if request.user != unit.staff and not request.user.is_staff:
        messages.error(request, 'You do not have permission to update this unit.')
        return redirect(reverse('unit-list-template'))

    if request.method == 'POST':
        unit.title = request.POST.get('title')
        unit.description = request.POST.get('description')
        unit.image = request.FILES.get('image', unit.image)  # Keep the old image if no new one is provided
        unit.save()
        return redirect(reverse('unit-list-template'))

    return render(request, 'unit/update_unit.html', {'unit': unit})


# Delete Unit
@login_required
def delete_unit_view(request, pk):
    unit = get_object_or_404(Unit, pk=pk)
    if request.user != unit.staff and not request.user.is_staff:
        messages.error(request, 'You do not have permission to delete this unit.')
        return redirect(reverse('unit-list-template'))

    if request.method == 'POST':
        unit.delete()
        return redirect(reverse('unit-list-template'))

    return render(request, 'delete_unit.html', {'unit': unit})


# Create Subject
@login_required
def create_subject_view(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        description = request.POST.get('description')
        image = request.FILES.get('image')

        Subject.objects.create(
            title=title,
            description=description,
            image=image,
            staff=request.user  # Set the staff as the current user
        )
        return redirect(reverse('subject-list-template'))

    return render(request, 'subject/create_subject.html')


# Update Subject
@login_required
def update_subject_view(request, pk):
    subject = get_object_or_404(Subject, pk=pk)
    if request.user != subject.staff and not request.user.is_staff:
        messages.error(request, 'You do not have permission to update this subject.')
        return redirect(reverse('subject-list-template'))

    if request.method == 'POST':
        subject.title = request.POST.get('title')
        subject.description = request.POST.get('description')
        subject.image = request.FILES.get('image', subject.image)  # Keep the old image if no new one is provided
        subject.save()
        return redirect(reverse('subject-list-template'))

    return render(request, 'suject/update_subject.html', {'subject': subject})


# Delete Subject
@login_required
def delete_subject_view(request, pk):
    subject = get_object_or_404(Subject, pk=pk)
    if request.user != subject.staff and not request.user.is_staff:
        messages.error


def topic_user(request, course_id=None):
    if course_id:
        # Get the course object based on the course_id provided
        course = get_object_or_404(Course, id=course_id)
        # Filter the topics based on the course
        topics = Topic.objects.filter(course=course)
    else:
        # If no course_id is passed, show all topics
        topics = Topic.objects.all()
        course = None  # Set course to None when not filtering by course

    context = {
        'topics': topics,  # Change 'topic' to 'topics' for clarity
        'course': course,
    }
    return render(request, 'topic_user.html', context)


@login_required
def list_blogs_view(request):
    blogs = Blog.objects.all()
    return render(request, 'blogs_list.html', {'blogs': blogs})


@login_required
def create_blog_view(request):
    if request.method == 'POST':
        title = request.POST.get('title')
        content = request.POST.get('content')
        image = request.FILES.get('image')  # Handle image upload

        blog = Blog.objects.create(
            title=title,
            content=content,
            image=image,
            author=request.user
        )

        # Add a success message
        messages.success(request, "Blog created successfully!")

        return redirect(reverse('blog_user'))  # Redirect to the success page

    return render(request, 'create_blog.html')


@login_required
def update_blog_view(request, pk):
    blog = get_object_or_404(Blog, pk=pk)
    if request.method == 'POST':
        blog.title = request.POST.get('title')
        blog.content = request.POST.get('content')
        if request.FILES.get('image'):  # Update image only if a new one is uploaded
            blog.image = request.FILES.get('image')
        blog.save()
        return redirect(reverse('blogs-list-template'))

    return render(request, 'update_blog.html', {'blog': blog})


@login_required
def delete_blog_view(request, pk):
    blog = get_object_or_404(Blog, pk=pk)
    if request.method == 'POST':
        blog.delete()
        return redirect(reverse('blogs-list-template'))
    return render(request, 'delete_blog.html', {'blog': blog})


def Blog_user(request):
    blogs = Blog.objects.all()
    return render(request, 'blog_user.html', {'blogs': blogs})


def retrieve_blog_view(request, pk):
    blog = get_object_or_404(Blog, pk=pk)
    return render(request, 'blog_detail.html', {'blog': blog})


# Like Blog
def like_blog(request, blog_id):
    blog = get_object_or_404(Blog, id=blog_id)
    blog.likes_count += 1  # Increment the like count
    blog.save()
    return redirect(reverse('blog-detail-template', args=[blog_id]))


# Comment on Blog
def comment_blog(request, blog_id):
    blog = get_object_or_404(Blog, id=blog_id)
    if request.method == 'POST':
        content = request.POST.get('comment')
        if content:
            Comment.objects.create(blog=blog, content=content, author=request.user)
    return redirect(reverse('blog-detail-template', args=[blog_id]))


logger = logging.getLogger(__name__)


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        logger.debug(f"Attempting login for user: {username}")

        user = authenticate(username=username, password=password)
        if user is None:
            logger.warning(f"Invalid credentials for user: {username}")
            return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

        # Ensure user is active
        if not user.is_active:
            logger.warning(f"User {username} is inactive.")
            return Response({'error': 'User is inactive'}, status=status.HTTP_401_UNAUTHORIZED)

        # Generate tokens
        refresh = RefreshToken.for_user(user)
        return Response({
            'access': str(refresh.access_token),
            'refresh': str(refresh),
            'username': user.username,
            'user_type': user.user_type,
        }, status=status.HTTP_200_OK)


def login(request):
    logger.debug("Entering the login function.")

    if request.method == 'POST':
        logger.debug("POST request received.")

        username = request.POST.get('username')
        password = request.POST.get('password')
        logger.debug(f"Username: {username}, Password: {'*' * len(password)}")

        user = authenticate(request, username=username, password=password)
        if user is not None:
            logger.debug("User authenticated successfully.")

            if user.is_active:
                logger.debug(f"User {username} is active.")
                auth_login(request, user)
                logger.info(f"User {username} logged in successfully.")

                # Save the session
                session_key = request.session.session_key
                UserSession.objects.create(user=user, session_key=session_key)

                logger.debug("Redirecting to the appropriate dashboard based on user type.")
                return redirect('dashboard')
            else:
                logger.warning(f"User {username} has an inactive account.")
                messages.error(request, 'Your account is inactive.')
        else:
            logger.warning(f"Authentication failed for user {username}. Invalid username or password.")
            messages.error(request, 'Invalid username or password.')

    logger.debug("Rendering the login page.")
    return render(request, 'login.html')


from django.contrib.auth import logout as auth_logout


def logout(request):
    logger.debug("Entering the logout function.")

    # Get the current user and session key
    user = request.user
    session_key = request.session.session_key

    # Log out the user
    auth_logout(request)
    logger.info("User logged out successfully.")

    # Delete the session entry
    UserSession.objects.filter(user=user, session_key=session_key).delete()

    messages.success(request, 'You have been logged out.')
    logger.debug("Redirecting to the open page after logout.")
    return redirect('dashboard')


def dashboard_view(request):
    return render(request, 'dashboard.html')  # Replace with your actual template


def quiz_view(request, quiz_id=None):
    if quiz_id:
        # Filter the questions based on the quiz
        quiz = Quiz.objects.get(id=quiz_id)
        questions = Questions.objects.filter(quiz=quiz)
    else:
        # If no quiz_id is passed, show all quizzes
        quizzes = Quiz.objects.all()

    context = {
        'quiz': quiz if quiz_id else None,
        'questions': questions if quiz_id else None,
        'quizzes': quizzes if not quiz_id else None,
    }
    return render(request, 'quiz_view.html', context)


def questions_view(request, quizname_id):
    quizname = get_object_or_404(QuizName, id=quizname_id)  # Get QuizName object
    no_of_questions = quizname.No_of_Questions
    # Fetch 50 random questions from the quizname
    questions = Questions.objects.filter(quizname=quizname).order_by('?')[:no_of_questions] # Filter by QuizName

    # Pass the quiz duration to the template
    quiz_duration = quizname.duration  # Assuming duration is in minutes

    if request.method == 'POST':
        return questions_submit(request, quizname, questions)

    return render(request, 'questions_view.html', {
        'quizname': quizname,
        'questions': questions,
        'quiz_duration': quiz_duration  # Pass duration to template
    })


def questions_submit(request, quizname_id):
    print(f"Received quizname_id: {quizname_id}")

    # Fetch the quizname with the given ID
    quizname = get_object_or_404(QuizName, id=quizname_id)  # Assuming QuizName is your model for quiz names
    print(f"Quizname found: {quizname}")

    # Fetch related questions for the quizname
    questions = Questions.objects.filter(quizname=quizname)
    print(f"Questions found for quizname: {len(questions)}")

    total_questions = len(questions)
    correct_answers = 0
    wrong_answers = 0
    attempted_questions = 0

    # Process user answers
    for question in questions:
        selected_option = request.POST.get(f'question_{question.id}')
        print(f"Question {question.id}, Selected Option: {selected_option}")

        if selected_option:  # If the user selected an option
            attempted_questions += 1
            # Check if the answer is correct
            if int(selected_option) == question.answer:
                correct_answers += 1
            else:
                wrong_answers += 1

    score = correct_answers
    print(f"Correct Answers: {correct_answers}, Wrong Answers: {wrong_answers}, Score: {score}")

    # Attempt to save quiz results
    try:
        QuizResult.objects.create(
            user=request.user,
            quizname=quizname,  # Saving the quizname association
            total_questions=total_questions,
            attempted_questions=attempted_questions,
            correct_answers=correct_answers,
            wrong_answers=wrong_answers,
            score=score
        )
        print("Quiz result saved successfully")
    except Exception as e:
        print(f"Error saving quiz result: {e}")

    # Prepare result summary for rendering
    result_summary = {
        'total_questions': total_questions,
        'attempted_questions': attempted_questions,
        'correct_answers': correct_answers,
        'wrong_answers': wrong_answers,
        'score': score,
    }

    return render(request, 'questions_result.html', {
        'quizname': quizname,  # Passing quizname to the template
        'result_summary': result_summary,
    })


def quizname_user_view(request):
    return render(request, 'quizname_user_view.html')


# Create Offer API View
class OfferCreateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        serializer = OfferSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Update Offer API View
class OfferUpdateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def put(self, request, pk, *args, **kwargs):
        offer = get_object_or_404(Offer, pk=pk)
        serializer = OfferSerializer(offer, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# Delete Offer API View
class OfferDeleteAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request, pk, *args, **kwargs):
        offer = get_object_or_404(Offer, pk=pk)
        offer.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


@login_required
@csrf_exempt
class OfferManagement(View):
    def get(self, request):
        offers = Offer.objects.all()
        return render(request, 'offers/offer_management.html', {'offers': offers})

    def post(self, request):
        action = request.POST.get('action')
        offer_id = request.POST.get('offer_id')
        code = request.POST.get('code')
        discount_percent = request.POST.get('discount_percent')
        valid_from = request.POST.get('valid_from')
        valid_until = request.POST.get('valid_until')

        # Create or Update Offer
        if action == 'create':
            offer = Offer.objects.create(
                code=code,
                discount_percent=discount_percent,
                valid_from=valid_from,
                valid_until=valid_until,
                created_by=request.user,
            )
            return JsonResponse({'status': 'Offer created successfully!', 'offer_id': offer.id}, status=201)

        elif action == 'update' and offer_id:
            offer = get_object_or_404(Offer, id=offer_id)
            offer.code = code
            offer.discount_percent = discount_percent
            offer.valid_from = valid_from
            offer.valid_until = valid_until
            offer.save()
            return JsonResponse({'status': 'Offer updated successfully!'}, status=200)

        elif action == 'delete' and offer_id:
            offer = get_object_or_404(Offer, id=offer_id)
            offer.delete()
            return JsonResponse({'status': 'Offer deleted successfully!'}, status=204)


# Mock test API View
def get_queryset(self):
    queryset = MockTest.objects.filter(user=self.request.user)
    print(queryset)  # Debug line
    return queryset


class MockTestViewSet(viewsets.ModelViewSet):
    serializer_class = MockTestSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Ensures users only access their own mock tests
        return MockTest.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        # Assigns the logged-in user as the owner of the MockTest
        serializer.save(user=self.request.user)


def assign_user(self, request, pk=None):
    """
        Custom action to assign the logged-in user to the MockTest.
        """
    mock_test = self.get_object()
    mock_test.user = request.user
    mock_test.save()
    return Response({'status': 'User assigned'})


from django.views.generic import ListView, DetailView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from .models import MockTest


class MockTestListView(LoginRequiredMixin, ListView):
    model = MockTest
    template_name = 'mocktest/mocktest_list.html'
    context_object_name = 'mocktests'

    def get_queryset(self):
        return MockTest.objects.filter(user=self.request.user)


from django.urls import reverse_lazy
from django.views.generic import CreateView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import MockTest, MockTestSubjectConfig, Subject


class MockTestCreateView(LoginRequiredMixin, CreateView):
    model = MockTest
    fields = ['duration']
    template_name = 'mocktest/mocktest_form.html'
    success_url = reverse_lazy('mocktest-list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['subjects'] = Subject.objects.all()
        return context

    def form_valid(self, form):
        form.instance.user = self.request.user
        mock_test = form.save()

        subjects = self.request.POST.getlist('subject')
        num_questions = self.request.POST.getlist('num_questions')
        max_scores = self.request.POST.getlist('max_score')

        for i in range(len(subjects)):
            MockTestSubjectConfig.objects.create(
                mock_test=mock_test,
                subject_id=subjects[i],
                num_questions=num_questions[i],
                max_score=max_scores[i]
            )

        return super().form_valid(form)


class MockTestUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = MockTest
    fields = ['duration', 'total_questions', 'total_max_score']
    template_name = 'mocktest/mocktest_form.html'
    success_url = reverse_lazy('mocktest-list')

    def test_func(self):
        # Ensure only the owner can update
        mock_test = self.get_object()
        return self.request.user == mock_test.user


class MockTestDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = MockTest
    template_name = 'mocktest/mocktest_confirm_delete.html'
    success_url = reverse_lazy('mocktest-list')

    def test_func(self):
        # Ensure only the owner can delete
        mock_test = self.get_object()
        return self.request.user == mock_test.user


def MockTest_user(request):
    mocktests = MockTest.objects.all()  # Retrieve all MockTest instances
    return render(request, 'mocktest/mock_test_user.html', {'mocktests': mocktests})


from django.views.generic import DetailView
from django.contrib.auth.mixins import LoginRequiredMixin
from .models import MockTest, UserResponse, Badge, Questions, MockTestSubjectConfig


"""class MockTestDetailView(LoginRequiredMixin, DetailView):
    model = MockTest
    template_name = 'mocktest/mocktest_detail.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Include the subject configuration for each mock test
        subject_configs = list(self.object.subject_configs.all().values('subject_id', 'num_questions', 'max_score'))
        context['subject_configs_json'] = json.dumps(subject_configs)  # Pass subject config data as JSON
        context['instructions'] = self.object.Instructions  # Display instructions
        return context

import json
import random
from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.db import transaction
from django.views.generic import DetailView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Sum
from .models import MockTest, UserResponse, Badge, Questions

class StartMockTestView(LoginRequiredMixin, DetailView):
    model = MockTest
    template_name = 'mocktest/start_test.html'

    def get(self, request, *args, **kwargs):
        mock_test = self.get_object()

        # Populate the test questions when starting the test
        mock_test.populate_questions()  # This will set questions for the test

        # Prepare context to send to the template
        context = {
            'mock_test': mock_test,
            'instructions': mock_test.Instructions,
            'duration': mock_test.duration.total_seconds() / 60  # Convert duration to minutes
        }
        return render(request, self.template_name, context)

    def populate_questions(self):
        # Get the subject configurations for the mock test
        configs = self.subject_configs.all()

        # Calculate total questions and max score by summing the fields from subject_configs
        self.total_questions = configs.aggregate(total_q=Sum('num_questions'))['total_q'] or 0
        self.total_max_score = configs.aggregate(total_score=Sum('max_score'))['total_score'] or 0

        selected_questions = []

        # Loop through each subject configuration
        for config in configs:
            # Correct the reference to 'Subject' (lowercase 'subject' to match model field)
            subject_questions = list(Questions.objects.filter(Subject=config.subject))

            # If there are questions for the subject, sample randomly based on the number required
            if subject_questions:
                sampled_questions = random.sample(subject_questions, min(len(subject_questions), config.num_questions))
                selected_questions.extend(sampled_questions)

        # Set the selected questions without saving them to the database
        self._set_questions(selected_questions)

    def post(self, request, *args, **kwargs):
        mock_test = self.get_object()

        # Get answers from the POST request (expecting a JSON object)
        user_answers = json.loads(request.POST.get('answers'))  # Assuming answers are posted as JSON

        correct_count = 0

        # Use atomic block to ensure database integrity
        with transaction.atomic():
            for question_id, selected_option in user_answers.items():
                # Get the question object or raise 404 if not found
                question = get_object_or_404(Questions, id=question_id)

                # Compare the selected option with the correct answer
                is_correct = int(selected_option) == question.answer
                correct_count += 1 if is_correct else 0

                # Save the user response to the database
                UserResponse.objects.create(
                    user=request.user,
                    question=question,
                    selected_option=selected_option,
                    is_correct=is_correct,
                    mock_test=mock_test
                )

        score = correct_count

        # Award badge based on score
        self.award_badge(request.user, score, mock_test)

        # Return the score and correct count as a JSON response
        return JsonResponse({'score': score, 'correct_count': correct_count})

    def award_badge(self, user, score, mock_test):
        Awards a badge based on the score achieved in the mock test.
        badge_type = None
        if score >= 90:
            badge_type = 'Gold'
        elif score >= 75:
            badge_type = 'Silver'
        elif score >= 50:
            badge_type = 'Bronze'

        if badge_type:
            # Create the badge for the user based on their score
            Badge.objects.create(user=user, mock_test=mock_test, badge_type=badge_type)

"""
from django.shortcuts import render, get_object_or_404
from .models import MockTest, Questions, MockTestSubjectConfig
import random

def mocktest_detailview(request, mocktest_id):
    mocktest = get_object_or_404(MockTest, id=mocktest_id)  # Get mocktest object

    # Get subject configurations for this mock test
    subject_configs = mocktest.subject_configs.all()  # Assuming MockTest has related field subject_configs

    questions = []
    total_questions = 0

    # Loop through each subject configuration and fetch random questions
    for config in subject_configs:
        # Fetch random questions for each subject based on num_questions
        subject_questions = Questions.objects.filter(Subject=config.subject).order_by('?')[:config.num_questions]
        questions.extend(subject_questions)
        total_questions += config.num_questions

    # Assuming the duration is stored as an integer or a timedelta
    duration = mocktest.duration  # Assuming duration is in minutes or seconds

    if request.method == 'POST':
        return test_submit(request, mocktest, questions)

    return render(request, 'mocktest/mocktest_detail.html', {
        'mocktest': mocktest,
        'questions': questions,
        'duration': duration,
        'total_questions': total_questions  # Pass total number of questions to template
    })


from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.db import transaction
from .models import MockTest, Questions, UserResponse, Badge
import json


def test_submit(request, mocktest, questions):
    user_answers = json.loads(request.POST.get('answers'))  # Get answers from the POST request

    correct_count = 0
    score = 0

    # Use atomic block to ensure database integrity when saving user responses
    with transaction.atomic():
        for question_id, selected_option in user_answers.items():
            question = get_object_or_404(Questions, id=question_id)  # Fetch question object

            # Check if the selected option matches the correct answer
            is_correct = int(selected_option) == question.answer
            correct_count += 1 if is_correct else 0

            # Save the user's response to the database
            UserResponse.objects.create(
                user=request.user,
                question=question,
                selected_option=selected_option,
                is_correct=is_correct,
                mock_test=mocktest
            )

        # Calculate score (you can adjust the calculation based on your requirements)
        score = correct_count

        # Award the badge based on the score
        award_badge(request.user, score, mocktest)

        # Respond with the score and correct count
        return JsonResponse({
            'score': score,
            'correct_count': correct_count,
            'badge': "Badge awarded based on score"  # Include badge info if needed
        })


def award_badge(user, score, mock_test):
    """Awards a badge based on the score achieved in the mock test."""
    badge_type = None
    if score >= 90:
        badge_type = 'Gold'
    elif score >= 75:
        badge_type = 'Silver'
    elif score >= 50:
        badge_type = 'Bronze'

    if badge_type:
        # Create the badge for the user based on their score
        Badge.objects.create(user=user, mock_test=mock_test, badge_type=badge_type)
