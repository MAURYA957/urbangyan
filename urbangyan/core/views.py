from bs4 import BeautifulSoup
from dateutil.parser import parser
from django.contrib.auth.hashers import check_password
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError
from django.contrib import messages
from django.urls import reverse
from numpy.random.mtrand import random
from rest_framework.decorators import action, permission_classes
from django.urls import reverse_lazy
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from rest_framework import viewsets, generics
from rest_framework.generics import get_object_or_404
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from django.contrib.auth import logout as auth_logout
from django.http import JsonResponse
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
from .models import (
    Blog,
    User,
    UserSession,
    Comment,
    Offer,
    MockTestSubjectConfig,
    Subject,
    SavedJob,
    ExperienceLevel,
    Order,
    Cart,
    AffairsCategory,
    AdSenseConfig, Subjectcatogary, News,
)
from django.contrib.auth import login as auth_login
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from .models import Topic, Course, Unit  # Ensure all necessary imports are present
from django.views.generic import ListView, CreateView, UpdateView, DeleteView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
import logging
from .models import Questions, MockTest
import uuid
import pandas as pd
from rest_framework.response import Response
from rest_framework import status
from rest_framework.decorators import api_view, parser_classes
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import (
    BlogSerializer,
    CourseSerializer,
    TopicSerializer,
    QuestionsSerializer,
    UserSerializer,
    CustomTokenObtainPairSerializer,
    UserSessionSerializer,
    SubjectSerializer,
    UnitSerializer,
    OfferSerializer,
    MockTestSerializer,
    SavedJobSerializer,
    ExperienceLevelSerializer,
    OrderSerializer,
    CartSerializer,
    AffairsCategorySerializer,
)

# Set up a logger
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


# =====================================
# 1. USER VIEWSET (Django REST Framework)
# =====================================
class UserViewSet(viewsets.ViewSet):
    permission_classes = [AllowAny]  # Public API for login and user creation

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
        data = request.data.copy()
        data.setdefault("is_visitor", True)  # Default to visitor

        serializer = UserSerializer(data=data)
        if serializer.is_valid():
            user = serializer.save()
            logger.info(f"User created successfully: {user.id}")

            # Handle many-to-many fields
            if "groups" in request.data:
                user.groups.set(request.data["groups"])
            if "user_permissions" in request.data:
                user.user_permissions.set(request.data["user_permissions"])

            # Generate JWT token
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            logger.info(f"Generated tokens for user {user.id}")

            return Response(
                {
                    "user": serializer.data,
                    "access": access_token,
                    "refresh": str(refresh),
                },
                status=status.HTTP_201_CREATED,
            )

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
            if "groups" in request.data:
                user.groups.set(request.data["groups"])
            if "user_permissions" in request.data:
                user.user_permissions.set(request.data["user_permissions"])

            return Response(serializer.data)

        logger.error(f"Validation errors on update: {serializer.errors}")
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def destroy(self, request, pk=None):
        logger.debug(f"Deleting user with ID: {pk}")
        user = get_object_or_404(User, pk=pk)
        user.delete()
        logger.info(f"User deleted successfully: {pk}")
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["post"])
    def login(self, request):
        """
        Custom login endpoint for authentication and token generation.
        """
        logger.debug("Attempting login with data: %s", request.data)
        identifier = request.data.get("identifier")  # Accepts email or phone
        password = request.data.get("password")

        # Ensure identifier and password are provided
        if not identifier or not password:
            logger.error("Missing identifier or password")
            return Response(
                {"error": "Identifier and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if the identifier is email or phone and find the user
        user = None
        if "@" in identifier:  # Assume it's an email if it contains '@'
            user = User.objects.filter(email=identifier).first()
        else:  # Otherwise, assume it's a phone number
            user = User.objects.filter(phone=identifier).first()

        # Authenticate user using password
        if user and user.check_password(password):
            logger.debug("User authenticated successfully.")

            if not user.is_active:
                logger.warning(f"Inactive user attempted login: {identifier}")
                return Response(
                    {"error": "User account is inactive."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)
            logger.info(f"User {identifier} authenticated successfully.")

            return Response(
                {
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "phone": user.phone,
                        "is_superuser": user.is_superuser,
                        "is_staff_user": user.is_staff_user,
                        "is_visitor": user.is_visitor,
                    },
                    "access": access_token,
                    "refresh": str(refresh),
                },
                status=status.HTTP_200_OK,
            )

        # If authentication fails
        logger.error(f"Failed login attempt for identifier: {identifier}")
        return Response(
            {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
        )


# =====================================
# 2. LOGIN FUNCTION (Django Authentication)
# =====================================
def login(request):
    logger.debug("Entering the login function.")

    if request.method == "POST":
        logger.debug("POST request received.")
        identifier = request.POST.get("identifier")  # Accepts email or phone
        password = request.POST.get("password")
        logger.debug(f"Identifier: {identifier}, Password: {'*' * len(password)}")

        # Check if the identifier is email or phone, and find the user
        user = None
        if "@" in identifier:  # Assume it's an email if it contains '@'
            user = User.objects.filter(email=identifier).first()
        else:  # Otherwise, assume it's a phone number
            user = User.objects.filter(phone=identifier).first()

        if user and user.check_password(password):
            logger.debug("User authenticated successfully.")

            if user.is_active:
                logger.debug(f"User {identifier} is active.")

                # Explicitly set the backend
                user.backend = "django.contrib.auth.backends.ModelBackend"

                auth_login(request, user)  # Log in the user
                logger.info(f"User {identifier} logged in successfully.")

                # Save session
                session_key = request.session.session_key or request.session.create()

                # Log out previous sessions
                active_sessions = UserSession.objects.filter(user=user)
                for session in active_sessions:
                    try:
                        session.logged_out_at = now()
                        session.save()
                    except Exception as e:
                        logger.error(
                            f"Error logging out session {session.session_key}: {e}"
                        )

                # Create a new session
                UserSession.objects.create(user=user, session_key=session_key)

                return redirect("dashboard")

            else:
                logger.warning(f"User {identifier} has an inactive account.")
                messages.error(request, "Your account is inactive.")

        else:
            logger.warning(f"Authentication failed for user {identifier}.")
            messages.error(request, "Invalid email/phone or password.")

    return render(request, "user/login.html")


# =====================================
# 3. LOGIN API VIEW (Django REST Framework)
# =====================================


class LoginAPIView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        identifier = (
            request.data.get("identifier", "").strip().lower()
        )  # Normalize input (email or phone)
        password = request.data.get("password")

        logger.info(f"Login attempt for: {identifier}")

        # Validate input
        if not identifier or not password:
            logger.error("Missing identifier or password")
            return Response(
                {"error": "Identifier and password are required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Check if identifier is email or phone
        user = None
        if "@" in identifier:  # Email validation
            user = User.objects.filter(email=identifier).first()
        else:  # Phone validation
            user = User.objects.filter(phone=identifier).first()

        # If the user is found and the password is correct
        if user and check_password(password, user.password):
            if not user.is_active:
                logger.warning(f"Inactive user attempted login: {identifier}")
                return Response(
                    {"error": "User account is inactive."},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            logger.info(f"User {user.id} ({identifier}) authenticated successfully")

            return Response(
                {
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "email": user.email,
                    "phone": user.phone,
                    "user_type": user.user_type,
                },
                status=status.HTTP_200_OK,
            )

        # If authentication fails
        logger.error(f"Invalid login attempt for identifier: {identifier}")
        return Response(
            {"error": "Invalid credentials."}, status=status.HTTP_401_UNAUTHORIZED
        )


def register_user(request):
    if request.method == "POST":
        full_name = request.POST.get("full_name", "").strip()
        email = request.POST.get("email", "").strip().lower()
        phone = request.POST.get("phone", "").strip()
        state = request.POST.get("state", "").strip()
        city = request.POST.get("city", "").strip()
        password = request.POST.get("password", "")

        # Validate required fields
        if not all([full_name, email, phone, password]):
            messages.error(request, "All fields are required.")
            return redirect("create-user")

        # Validate email and phone format (basic validation)
        if "@" not in email or "." not in email:
            messages.error(request, "Invalid email format.")
            return redirect("create-user")
        if not phone.isdigit() or len(phone) < 10:
            messages.error(request, "Invalid phone number.")
            return redirect("create-user")

        image = request.FILES.get("image")

        try:
            # Create user instance
            user = User.objects.create_user(
                full_name=full_name,
                email=email,
                phone=phone,
                state=state,
                city=city,
                password=password,  # Django's `create_user` hashes password
                image=image,
                is_active=True,
            )

            messages.success(request, "User created successfully!")
            return redirect("login")

        except IntegrityError:
            messages.error(
                request, "Email or Phone number is already registered. Please login."
            )
            return redirect("create-user")

        except Exception as e:
            messages.error(request, "An error occurred while creating the user.")
            return JsonResponse({"error": str(e)}, status=400)

    return render(request, "user/create_user.html")


@login_required
def update_user_view(request, pk):
    # Fetch the user to update
    user = get_object_or_404(User, pk=pk)

    # Ensure the logged-in user can only update their own profile
    if user != request.user:
        messages.error(request, "You can only update your own profile.")
        return redirect("profile")

    # Handle POST request
    if request.method == "POST":
        # Get form data
        full_name = request.POST.get("full_name")
        email = request.POST.get("email")
        phone = request.POST.get("phone")
        state = request.POST.get("state")
        city = request.POST.get("city")
        password = request.POST.get("password")
        image = request.FILES.get("image")

        # Update user details
        user.full_name = full_name
        user.email = email
        user.phone = phone
        user.state = state
        user.city = city

        if image:
            user.image = image

        # Update password if provided
        if password:
            user.set_password(password)

        # Save the updated user instance
        user.save()

        # Success message
        messages.success(request, "Profile updated successfully!")

        # Redirect after successful update
        return redirect(
            reverse("dashboard")
        )  # Replace 'profile' with the appropriate URL name

    # Render the update user form
    return render(request, "user/update_user.html", {"user": user})


@login_required
def delete_user_view(request, pk):
    """
    Allow a user to delete their own account with a confirmation prompt.
    """
    user = get_object_or_404(User, pk=pk)

    # Ensure the logged-in user can only delete their own account
    if request.user != user:
        messages.error(request, "You can only delete your own account.")
        return redirect(
            reverse("dashboard")
        )  # Redirect to the home page or any other page.

    if request.method == "POST":
        user.delete()
        messages.success(request, "Your account has been deleted successfully.")
        return redirect(
            reverse("dashboard")
        )  # Redirect to the home page after deletion.

    return render(request, "user/delete_user.html", {"user": user})


class UserSessionListCreateAPIView(generics.ListCreateAPIView):
    queryset = UserSession.objects.all()
    serializer_class = UserSessionSerializer
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        """Override the create method to set the user from the request."""
        serializer.save(
            user=self.request.user, session_key=self.request.session.session_key
        )


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
        return Response(
            {"detail": "You do not have permission to delete this course."},
            status=status.HTTP_403_FORBIDDEN,
        )


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
        return Response(
            {"detail": "You do not have permission to delete this topic."},
            status=status.HTTP_403_FORBIDDEN,
        )


@login_required
def create_course_view(request):
    try:
        if request.method == "POST":
            # Step 1: Log the start of the course creation
            logger.info("Course creation started by user: %s", request.user.full_name)

            # Step 2: Retrieve form data
            title = request.POST.get("title")
            description = request.POST.get("description")
            image = request.FILES.get("image")
            price = request.POST.get("price")
            subjects_ids = request.POST.getlist("subjects")

            logger.debug(
                f"Form data retrieved - Title: {title}, Price: {price}, Subjects: {subjects_ids}"
            )

            # Step 3: Create the Course object without subjects or staff directly
            course = Course.objects.create(
                title=title,
                description=description,
                image=image,
                price=price,
                Staff=request.user.full_name,  # Assign the current user as staff
            )
            logger.info("Course created: %s", course.title)

            # Step 4: Associate selected subjects with the course
            course.subjects.set(subjects_ids)
            course.save()

            logger.info("Subjects associated with course: %s", subjects_ids)

            # Step 5: Success message and redirect
            messages.success(request, "Course created successfully!")
            logger.info("Success message displayed, redirecting to course list.")

            return redirect(reverse("course-user-template"))

        # Step 6: Render the form if GET request
        subjects = Subject.objects.all()
        logger.info("Course creation form rendered.")
        return render(request, "courses/create_course.html", {"subjects": subjects})

    except Exception as e:
        # Step 7: Handle any errors and log them
        logger.error("Error during course creation: %s", str(e))
        messages.error(request, "An error occurred while creating the course.")
        return redirect(reverse("create_course.html"))

    except Exception as e:
        # Step 7: Handle any errors and log them
        logger.error("Error during course creation: %s", str(e))
        messages.error(request, "An error occurred while creating the course.")
        return redirect(reverse("course-list-template"))


@login_required
def update_course_view(request, pk):
    try:
        course = get_object_or_404(Course, pk=pk)

        # Step 1: Check permissions
        if request.user.full_name != course.Staff and not request.user.is_staff:
            messages.error(request, "You do not have permission to update this course.")
            logger.warning(
                "User %s attempted to update course without permission.",
                request.user.full_name,
            )
            return redirect(reverse("course-list-template"))

        # Step 2: Handle POST request (updating course)
        if request.method == "POST":
            logger.info(
                "User %s updating course: %s", request.user.full_name, course.title
            )

            # Update course fields
            course.title = request.POST.get("title")
            course.description = request.POST.get("description")
            course.image = request.FILES.get(
                "image", course.image
            )  # Keep old image if none provided
            course.price = request.POST.get("price")

            # Updating the subjects (many-to-many field)
            subjects_ids = request.POST.getlist("subjects")
            course.subjects.set(subjects_ids)

            course.save()
            logger.info("Course updated: %s", course.title)

            messages.success(request, "Course updated successfully!")
            return redirect(reverse("course-list-template"))

        # Step 3: Render form for GET request
        subjects = Subject.objects.all()
        logger.info("Rendering course update form for course: %s", course.title)
        return render(
            request,
            "courses/update_course.html",
            {"course": course, "subjects": subjects},
        )

    except Exception as e:
        logger.error("Error updating course: %s", str(e))
        messages.error(request, "An error occurred while updating the course.")
        return redirect(reverse("course-list-template"))


@login_required
def delete_course_view(request, pk):
    try:
        course = get_object_or_404(Course, pk=pk)

        # Step 1: Check permissions
        if request.user.full_name != course.Staff and not request.user.is_staff:
            messages.error(request, "You do not have permission to delete this course.")
            logger.warning(
                "User %s attempted to delete course without permission.",
                request.user.full_name,
            )
            return redirect(reverse("course-list-template"))

        # Step 2: Handle POST request (deleting course)
        if request.method == "POST":
            logger.info(
                "User %s deleting course: %s", request.user.full_name, course.title
            )
            course.delete()
            logger.info("Course deleted: %s", course.title)
            messages.success(request, "Course deleted successfully!")
            return redirect(reverse("course-list-template"))

        # Step 3: Render confirmation page for GET request
        logger.info("Rendering delete confirmation for course: %s", course.title)
        return render(request, "courses/delete_course.html", {"course": course})

    except Exception as e:
        logger.error("Error deleting course: %s", str(e))
        messages.error(request, "An error occurred while deleting the course.")
        return redirect(reverse("course-list-template"))


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
        return Response(
            {"detail": "You do not have permission to delete this topic."},
            status=status.HTTP_403_FORBIDDEN,
        )


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
        return Response(
            {"detail": "You do not have permission to delete this unit."},
            status=status.HTTP_403_FORBIDDEN,
        )


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
        return Response(
            {"detail": "You do not have permission to delete this subject."},
            status=status.HTTP_403_FORBIDDEN,
        )


# to be checked followings
def course_user(request):
    courses = Course.objects.all()
    return render(request, "courses/course_user.html", {"courses": courses})


def list_courses_view(request):
    courses = Course.objects.all()
    return render(request, "courses/course_list.html", {"courses": courses})


def list_topics_view(request):
    topics = Topic.objects.all()
    return render(request, "topic/topic_list.html", {"topics": topics})


def list_subjects_view(request):
    subjects = Subject.objects.all()
    return render(request, "subject/list_subjects_view.html", {"subjects": subjects})


def list_units_view(request):
    units = Unit.objects.all()
    return render(request, "unit/list_units_view.html", {"units": units})


@login_required
def list_questions_view(request):
    questions = Questions.objects.all()
    subjects = Questions.objects.values_list("Subject__name", flat=True).distinct()
    units = Questions.objects.values_list("unit", flat=True).distinct()
    topics = Questions.objects.values_list("topic", flat=True).distinct()

    context = {
        "questions": questions,
        "subjects": subjects,
        "units": units,
        "topics": topics,
    }
    return render(request, "question/questions_list.html", context)


def filter_units(request):
    subject_id = request.GET.get("subject_id")
    logger.info(f"Received subject_id: {subject_id}")
    if subject_id:
        units = Unit.objects.filter(subject_id=subject_id).values("id", "title")
        logger.info(f"Units found: {list(units)}")
        return JsonResponse({"units": list(units)})
    logger.warning("No subject_id provided or no units found")
    return JsonResponse({"units": []})


def filter_topics(request):
    unit_id = request.GET.get("unit_id")
    logger.info(f"Received unit_id: {unit_id}")
    if unit_id:
        topics = Topic.objects.filter(unit_id=unit_id).values("id", "topic")
        logger.info(f"Topics found: {list(topics)}")
        return JsonResponse({"topics": list(topics)})
    logger.warning("No unit_id provided or no topics found")
    return JsonResponse({"topics": []})


@login_required
def create_question_view(request):
    if request.method == "POST":
        try:
            # Get data from the POST request_
            subject_id = request.POST.get("subject")  # Subject ID
            unit_id = request.POST.get("unit")  # Unit ID
            topic_id = request.POST.get("topic")  # Topic ID
            question_level = request.POST.get("question_level")  # Question level

            # Fetch related objects
            subject = get_object_or_404(Subject, pk=subject_id)
            unit = get_object_or_404(Unit, pk=unit_id)
            topic = get_object_or_404(Topic, pk=topic_id)

            # Fetch question details
            question = request.POST.get("question")
            option_1 = request.POST.get("option_1")
            option_2 = request.POST.get("option_2")
            option_3 = request.POST.get("option_3")
            option_4 = request.POST.get("option_4")
            answer = request.POST.get("answer")
            explanation = request.POST.get("explanation")

            # Create the question
            Questions.objects.create(
                Subject=subject,
                unit=unit,
                topic=topic,
                question_level=question_level,
                question=question,
                option_1=option_1,
                option_2=option_2,
                option_3=option_3,
                option_4=option_4,
                answer=answer,
                explanation=explanation,
            )

            # Log success and notify user
            logger.info("Question created successfully: %s", question)
            messages.success(request, "Question created successfully!")

            return redirect(reverse("questions-list-template"))

        except Exception as e:
            logger.error("Error creating question: %s", str(e))
            messages.error(request, "An error occurred while creating the question.")

    # Fetch data for dropdowns
    subjects = Subject.objects.all()

    return render(
        request,
        "question/create_question.html",
        {
            "subjects": subjects,
        },
    )


@login_required
def update_question_view(request, pk):
    question = get_object_or_404(Questions, pk=pk)
    subjects = Subject.objects.all()  # Fetch all subjects for the dropdown

    if request.method == "POST":
        question.Subject = get_object_or_404(
            Subject, pk=request.POST.get("subject")
        )  # New subject field
        question.question = request.POST.get("question")
        question.option_1 = request.POST.get("option_1")
        question.option_2 = request.POST.get("option_2")
        question.option_3 = request.POST.get("option_3")
        question.option_4 = request.POST.get("option_4")
        question.answer = request.POST.get("answer")
        question.explanation = request.POST.get("explanation")
        question.question_level = request.POST.get(
            "question_level"
        )  # New question level field

        question.save()

        # Add a success message
        messages.success(request, "Question updated successfully!")

        return redirect(reverse("questions-list-template"))

    return render(
        request,
        "question/update_question.html",
        {
            "question": question,
            "subjects": subjects,  # Pass subjects to the template for the dropdown
        },
    )


@login_required
def delete_question_view(request, pk):
    question = get_object_or_404(Questions, pk=pk)

    if request.method == "POST":
        question.delete()
        messages.success(
            request, "Question deleted successfully!"
        )  # Add success message
        return redirect(reverse("questions-list-template"))

    return render(request, "question/delete_question.html", {"question": question})


def get_units(request, subject_id):
    try:
        # Fetch units related to the provided subject ID
        units = Unit.objects.filter(subject_id=subject_id).values("id", "title")
        return JsonResponse({"units": list(units)}, status=200)
    except Exception as e:
        return JsonResponse({"error": "Error loading units"}, status=500)


from django.db import transaction
import logging

# Initialize logger
logger = logging.getLogger(__name__)


@login_required
def create_topic_view(request):
    if request.method == "POST":
        topic_name = request.POST.get("topic")
        description = request.POST.get("description")
        image = request.FILES.get("image")
        subject_id = request.POST.get("subject")
        unit_id = request.POST.get("unit")

        try:
            # Fetch the course (required)

            # Fetch subject and unit (optional)
            subject = get_object_or_404(Subject, pk=subject_id) if subject_id else None
            unit = get_object_or_404(Unit, pk=unit_id) if unit_id else None

            with transaction.atomic():
                # Create the topic
                Topic.objects.create(
                    topic=topic_name,
                    description=description,
                    image=image,
                    staff=request.user,  # Set the staff as the current user
                    subject=subject,
                    unit=unit,
                )

            # Log and notify success
            logger.info(
                f"Topic '{topic_name}' created successfully by {request.user.full_name}."
            )
            messages.success(request, "Topic created successfully.")
            return redirect(reverse("topic-list-template"))  # Redirect to topic list

        except Exception as e:
            # Log error details
            logger.error(
                f"Error creating topic '{topic_name}' by {request.user.full_name}: {e}"
            )
            messages.error(
                request, "An error occurred while creating the topic. Please try again."
            )

    # Handle GET request: Pass available courses, subjects, and units to the form
    subjects = Subject.objects.all()
    units = Unit.objects.all()

    return render(
        request,
        "topic/create_topic.html",
        {
            "subjects": subjects,
            "units": units,
        },
    )


@login_required
def update_topic_view(request, pk):
    # Fetch the topic or return a 404 if not found
    topic = get_object_or_404(Topic, pk=pk)

    # Check if the user has permission to update the topic
    if request.user != topic.staff and not request.user.is_staff:
        messages.error(request, "You do not have permission to update this topic.")
        return redirect(reverse("topic-list-template"))

    if request.method == "POST":
        # Fetch input data
        topic_name = request.POST.get("topic")
        description = request.POST.get("description")
        new_image = request.FILES.get("image")
        subject_id = request.POST.get("subject")
        unit_id = request.POST.get("unit")

        # Validate required fields
        if not topic_name or not description:
            messages.error(request, "Topic name and description are required.")
            return render(request, "topic/update_topic.html", {"topic": topic})

        # Update the topic fields
        topic.topic = topic_name
        topic.description = description
        if new_image:
            topic.image = new_image

        # Handle subject and unit relationships
        try:
            if subject_id:
                subject = get_object_or_404(Subject, pk=subject_id)
                topic.subject = subject  # Update the related subject
            if unit_id:
                unit = get_object_or_404(Unit, pk=unit_id)
                topic.unit = unit  # Update the related unit
        except Subject.DoesNotExist:
            messages.error(request, "The selected subject does not exist.")
        except Unit.DoesNotExist:
            messages.error(request, "The selected unit does not exist.")

        # Save changes to the topic
        try:
            topic.save()
            messages.success(request, "Topic updated successfully.")
            return redirect(reverse("topic-list-template"))
        except Exception as e:
            messages.error(request, f"An error occurred while updating the topic: {e}")

    # Preload subject and unit options for the update form
    subjects = Subject.objects.all()
    units = Unit.objects.filter(subject=topic.subject) if topic.subject else []

    return render(
        request,
        "topic/update_topic.html",
        {
            "topic": topic,
            "subjects": subjects,
            "units": units,
        },
    )


# Delete Topic
@login_required
def delete_topic_view(request, pk):
    topic = get_object_or_404(Topic, pk=pk)

    # Check for permission
    if request.user != topic.staff and not request.user.is_staff:
        messages.error(request, "You do not have permission to delete this topic.")
        return redirect(reverse("topic-list-template"))

    if request.method == "POST":
        topic.delete()
        messages.success(request, "Topic deleted successfully.")
        return redirect(reverse("topic-list-template"))

    return render(request, "topic/delete_topic.html", {"topic": topic})


# Similar logic for Unit and Subject follows the same pattern:


# Create Unit
@login_required
def create_unit_view(request):
    if request.method == "POST":
        title = request.POST.get("title")
        subject_id = request.POST.get("subject")

        # Fetch the subject based on the ID
        subject = Subject.objects.get(id=subject_id) if subject_id else None

        if subject:
            # Create the Unit object
            Unit.objects.create(
                title=title,
                subject=subject,  # Set the subject from the dropdown
            )
            return redirect(reverse("unit-list-template"))
        else:
            error = "Please select a valid subject."

            # Pass error message along with the subjects
            subjects = Subject.objects.all()
            return render(
                request, "unit/create_unit.html", {"subjects": subjects, "error": error}
            )

    # If GET request, just pass subjects to the template
    subjects = Subject.objects.all()
    return render(request, "unit/create_unit.html", {"subjects": subjects})


@login_required
def update_unit_view(request, pk):
    unit = get_object_or_404(Unit, pk=pk)

    # Fetch all subjects to populate the dropdown
    subjects = Subject.objects.all()

    if request.method == "POST":
        # Fetch and update unit fields from the form
        subject_id = request.POST.get("subject")  # Get subject ID from the form
        if subject_id:
            unit.subject = get_object_or_404(
                Subject, id=subject_id
            )  # Update subject based on the ID

        unit.title = request.POST.get("title")

        # If an image is uploaded, replace the old one with the new one

        # Save the unit with the updated information
        unit.save()

        # Show a success message and redirect to the unit list page
        messages.success(request, "Unit updated successfully.")
        return redirect(reverse("unit-list-template"))

    # If GET request, render the unit update form with the current unit data
    return render(
        request, "unit/update_unit.html", {"unit": unit, "subjects": subjects}
    )


# Delete Unit
@login_required
def delete_unit_view(request, pk):
    unit = get_object_or_404(Unit, pk=pk)

    if request.method == "POST":
        # If POST request, delete the unit and redirect to the unit list
        unit.delete()
        messages.success(request, "Unit deleted successfully.")
        return redirect(reverse("unit-list-template"))

    # If GET request, render the confirmation page with the unit to be deleted
    return render(request, "unit/delete_unit.html", {"unit": unit})


# Create Subject
@login_required
def create_subject_view(request):
    if request.method == "POST":
        # Retrieve form data
        name = request.POST.get("name")
        image = request.FILES.get("image")
        authors = request.POST.get("authors")  # Expecting comma-separated author names

        # Validate required fields
        if not name:
            return render(
                request,
                "subject/create_subject.html",
                {
                    "error": "Name are required fields.",
                    "form_data": request.POST,  # Pass form data back to prefill
                },
            )

        # Create the Subject instance
        Subject.objects.create(
            name=name, image=image, authors=authors  # Store comma-separated authors
        )

        # Redirect to the subject list page
        return redirect(reverse("subject-list-template"))

    # Render form template
    return render(request, "subject/create_subject.html")


# Update Subject
@login_required
def update_subject_view(request, pk):
    subject = get_object_or_404(Subject, pk=pk)

    # Authorization: Ensure only authorized users can update
    if not request.user.is_staff:
        messages.error(request, "You do not have permission to update this subject.")
        return redirect(reverse("subject-list-template"))

    if request.method == "POST":
        name = request.POST.get("name")
        image = request.FILES.get("image")

        # Validate required fields
        if not name:
            messages.error(request, "Name are required.")
            return render(request, "subject/update_subject.html", {"subject": subject})

        # Update the subject details
        subject.name = name
        if image:  # Only update image if a new one is provided
            subject.image = image
        subject.save()

        messages.success(request, f'Subject "{subject.name}" updated successfully.')
        return redirect(reverse("subject-list-template"))

    # Render the update form
    return render(request, "subject/update_subject.html", {"subject": subject})


def delete_subject_view(request, pk):
    # Get the subject object, or return a 404 if not found
    subject = get_object_or_404(Subject, pk=pk)

    # Check if the current user is either the staff of the subject or an admin (superuser)
    if request.user != subject.authors and not request.user.is_staff:
        messages.error(request, "You do not have permission to delete this subject.")
        return redirect(
            "subject-list-template"
        )  # Redirect to subject list if unauthorized

    # If the request method is POST, proceed to delete
    if request.method == "POST":
        subject.delete()
        messages.success(request, "Subject deleted successfully.")
        return redirect("subject-list-template")  # Redirect after deletion

    # Otherwise, show a confirmation page
    return render(request, "subject/confirm_delete.html", {"subject": subject})


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
        "topics": topics,  # Change 'topic' to 'topics' for clarity
        "course": course,
    }
    return render(request, "topic/topic_user.html", context)


@login_required
def list_blogs_view(request):
    blogs = Blog.objects.all()
    return render(request, "blog/blogs_list.html", {"blogs": blogs})


@login_required
def create_blog_view(request):
    if request.method == "POST":
        title = request.POST.get("title")
        content = request.POST.get("content")
        image = request.FILES.get("image")  # Handle image upload

        blog = Blog.objects.create(
            title=title, content=content, image=image, author=request.user
        )

        # Add a success message
        messages.success(request, "Blog created successfully!")

        return redirect(reverse("blog_user"))  # Redirect to the success page

    return render(request, "blog/create_blog.html")


@login_required
def update_blog_view(request, pk):
    blog = get_object_or_404(Blog, pk=pk)
    if request.method == "POST":
        blog.title = request.POST.get("title")
        blog.content = request.POST.get("content")
        if request.FILES.get("image"):  # Update image only if a new one is uploaded
            blog.image = request.FILES.get("image")
        blog.save()
        return redirect(reverse("blogs-list-template"))

    return render(request, "blog/update_blog.html", {"blog": blog})


@login_required
def delete_blog_view(request, pk):
    blog = get_object_or_404(Blog, pk=pk)
    if request.method == "POST":
        blog.delete()
        return redirect(reverse("blogs-list-template"))
    return render(request, "blog/delete_blog.html", {"blog": blog})


def Blog_user(request):
    blogs = Blog.objects.all()
    return render(request, "blog/blog_user.html", {"blogs": blogs})


def retrieve_blog_view(request, pk):
    blog = get_object_or_404(Blog, id=pk)
    comments = blog.comments.all().order_by("-created_at")
    return render(
        request,
        "blog/blog_detail.html",
        {
            "blog": blog,
            "comments": comments,
        },
    )


# Like Blog
def like_blog(request, blog_id):
    blog = get_object_or_404(Blog, id=blog_id)
    blog.likes_count += 1  # Increment the like count
    blog.save()
    return redirect(reverse("blog-detail-template", args=[blog_id]))


def comment_blog(request, blog_id):
    blog = get_object_or_404(Blog, id=blog_id)

    if request.method == "POST":
        content = request.POST.get("content")  # Match field name in form
        if content:
            Comment.objects.create(
                blog=blog,
                content=content,
                author=request.user,
            )
        return redirect(reverse("blog-detail-template", args=[blog_id]))

    return redirect(reverse("blog-detail-template", args=[blog_id]))


def logout(request):
    logger.debug("Entering the logout function.")

    # Get the current user and session key
    user = request.user
    session_key = request.session.session_key

    # Log out the user
    auth_logout(request)
    logger.info("User logged out successfully.")

    # Update the logout time in the user's session record
    try:
        user_session = UserSession.objects.filter(
            user=user, session_key=session_key
        ).first()
        if user_session:
            user_session.logged_out_at = now()
            user_session.save()
            logger.info(
                f"Updated logout time for session {session_key} of user {user.full_name}."
            )
        else:
            logger.warning(
                f"No session found for user {user.full_name} with session key {session_key}."
            )
    except Exception as e:
        logger.error(f"Error updating logout time for session {session_key}: {str(e)}")

    messages.success(request, "You have been logged out.")
    logger.debug("Redirecting to the open page after logout.")
    return redirect("dashboard")


def dashboard_view(request):
    return render(request, "dashboard.html")  # Replace with your actual template


def quiz(request):
    subject_id = request.GET.get("subject_id")
    unit_id = request.GET.get("unit_id")
    topic_id = request.GET.get("topic_id")

    if bool(subject_id) + bool(unit_id) + bool(topic_id) != 1:
        return JsonResponse(
            {
                "error": "Please provide exactly one of subject_id, unit_id, or topic_id."
            },
            status=400,
        )

    if subject_id:
        obj = get_object_or_404(Subject, id=subject_id)
        questions = list(Questions.objects.filter(Subject=obj).order_by("?"))
    elif unit_id:
        obj = get_object_or_404(Unit, id=unit_id)
        questions = list(Questions.objects.filter(unit=obj).order_by("?"))
    elif topic_id:
        obj = get_object_or_404(Topic, id=topic_id)
        questions = list(Questions.objects.filter(topic=obj).order_by("?"))

    if not questions:
        # Check if the user has provided a valid subject, unit, or topic
        if subject_id:
            error_message = "Oops! No questions are available for the selected subject."
            logger.warning(f"No questions found for subject ID: {subject_id}")
        elif unit_id:
            error_message = "Oops! No questions are available for the selected unit."
            logger.warning(f"No questions found for unit ID: {unit_id}")
        elif topic_id:
            error_message = "Oops! No questions are available for the selected topic."
            logger.warning(f"No questions found for topic ID: {topic_id}")
        else:
            error_message = "Oops! No questions found for the selected filter."
            logger.warning(
                "No questions found for the selected filter (no subject, unit, or topic provided)."
            )

        return render(
            request, "quiz/subjecterror.html", {"error_message": error_message}
        )

    total_questions = len(questions)
    num_sets = (total_questions // 20) + (1 if total_questions % 20 != 0 else 0)

    question_sets = [
        {"set_number": i + 1, "questions": questions[start_index:end_index]}
        for i, (start_index, end_index) in enumerate(
            [(i * 20, min((i + 1) * 20, total_questions)) for i in range(num_sets)]
        )
    ]

    for question_set in question_sets:
        total_seconds = len(question_set["questions"]) * 15  # 15 seconds per question
        minutes = total_seconds // 60
        seconds = total_seconds % 60
        question_set["set_duration"] = f"{minutes} Min {seconds} Sec"

    context = {
        "question_sets": question_sets,
    }

    return render(request, "quiz/quiz.html", context)


def submit_quiz(request):
    if request.method == "POST":
        user = request.user
        submitted_data = request.POST  # Dictionary of submitted answers
        quiz_set = submitted_data.get(
            "quiz_set", "Set_1"
        )  # Default to Set_1 if not provided
        total_questions = 0
        attempted_questions = 0
        correct_answers = 0
        wrong_answers = 0
        question_results = []

        for key, value in submitted_data.items():
            if key.startswith("question_"):  # Identify submitted answers
                question_id = key.split("_")[1]
                question = get_object_or_404(Questions, id=question_id)
                selected_answer = int(value) if value.isdigit() else None
                correct_answer = question.answer

                total_questions += 1
                if selected_answer:
                    attempted_questions += 1
                    if selected_answer == correct_answer:
                        correct_answers += 1
                        status = "Correct"
                    else:
                        wrong_answers += 1
                        status = "Incorrect"
                else:
                    status = "Unattempted"

                question_results.append(
                    {
                        "question": question.question,
                        "selected_answer": (
                            selected_answer if selected_answer else "Not Answered"
                        ),
                        "correct_answer": correct_answer,
                        "attempted": "Yes" if selected_answer else "No",
                        "status": status,
                    }
                )

        # Calculate percentage score
        score = (correct_answers / total_questions) * 100 if total_questions else 0

        # Save the result
        if request.user.is_authenticated:
            QuizResult.objects.create(
                user=user,
                quiz=quiz_set,
                total_questions=total_questions,
                attempted_questions=attempted_questions,
                correct_answers=correct_answers,
                wrong_answers=wrong_answers,
                score=score,
            )
        else:
            pass

        context = {
            "total_questions": total_questions,
            "attempted_questions": attempted_questions,
            "correct_answers": correct_answers,
            "wrong_answers": wrong_answers,
            "unattempted_questions": total_questions - attempted_questions,
            "score": score,
            "question_results": question_results,
        }

        return render(request, "quiz/result.html", context)

    return JsonResponse({"error": "Invalid request method"}, status=400)


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
        return render(request, "offers/offer_management.html", {"offers": offers})

    def post(self, request):
        action = request.POST.get("action")
        offer_id = request.POST.get("offer_id")
        code = request.POST.get("code")
        discount_percent = request.POST.get("discount_percent")
        valid_from = request.POST.get("valid_from")
        valid_until = request.POST.get("valid_until")

        # Create or Update Offer
        if action == "create":
            offer = Offer.objects.create(
                code=code,
                discount_percent=discount_percent,
                valid_from=valid_from,
                valid_until=valid_until,
                created_by=request.user,
            )
            return JsonResponse(
                {"status": "Offer created successfully!", "offer_id": offer.id},
                status=201,
            )

        elif action == "update" and offer_id:
            offer = get_object_or_404(Offer, id=offer_id)
            offer.code = code
            offer.discount_percent = discount_percent
            offer.valid_from = valid_from
            offer.valid_until = valid_until
            offer.save()
            return JsonResponse({"status": "Offer updated successfully!"}, status=200)

        elif action == "delete" and offer_id:
            offer = get_object_or_404(Offer, id=offer_id)
            offer.delete()
            return JsonResponse({"status": "Offer deleted successfully!"}, status=204)


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
    return Response({"status": "User assigned"})


class MockTestListView(LoginRequiredMixin, ListView):
    model = MockTest
    template_name = "mocktest/mocktest_list.html"
    context_object_name = "mocktests"

    def get_queryset(self):
        return MockTest.objects.filter(user=self.request.user)


class MockTestCreateView(LoginRequiredMixin, CreateView):
    model = MockTest
    fields = [
        "duration",
        "negative_mark",
        "Exam_Name",
        "Instructions",
        "total_questions",
        "total_max_score",
    ]
    template_name = "mocktest/mocktest_form.html"
    success_url = reverse_lazy("mocktest-list")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["subjects"] = Subject.objects.all()
        return context

    def form_valid(self, form):
        form.instance.user = self.request.user
        mock_test = form.save()

        subjects = self.request.POST.getlist("subject")
        num_questions = self.request.POST.getlist("num_questions")
        max_scores = self.request.POST.getlist("max_score")

        total_questions = 0
        total_max_score = 0

        # Create MockTestSubjectConfig entries and calculate totals
        for i in range(len(subjects)):
            subject_id = subjects[i]
            num_questions_val = num_questions[i]
            max_score_val = max_scores[i]

            try:
                subject_config = MockTestSubjectConfig.objects.create(
                    mock_test=mock_test,
                    subject_id=subject_id,
                    num_questions=num_questions_val,
                    max_score=max_score_val,
                )
                logger.debug(
                    f"SubjectConfig created: Subject ID={subject_id}, Questions={num_questions_val}, Max Score={max_score_val}."
                )
                total_questions += int(num_questions_val)
                total_max_score += int(max_score_val)
            except Exception as e:
                logger.error(
                    f"Error creating SubjectConfig for Subject ID={subject_id}: {e}"
                )

            # Update totals for the Mock Test
            mock_test.total_questions = total_questions
            mock_test.total_max_score = total_max_score
            mock_test.save(update_fields=["total_questions", "total_max_score"])
            logger.info(
                f"Mock Test '{mock_test.Exam_Name}' updated with totals: Questions={total_questions}, Max Score={total_max_score}."
            )

        return super().form_valid(form)


class MockTestUpdateView(LoginRequiredMixin, UserPassesTestMixin, UpdateView):
    model = MockTest
    fields = ["duration", "total_questions", "total_max_score"]
    template_name = "mocktest/mocktest_form.html"
    success_url = reverse_lazy("mocktest-list")

    def test_func(self):
        # Ensure only the owner can update
        mock_test = self.get_object()
        return self.request.user == mock_test.user


class MockTestDeleteView(LoginRequiredMixin, UserPassesTestMixin, DeleteView):
    model = MockTest
    template_name = "mocktest/mocktest_confirm_delete.html"
    success_url = reverse_lazy("mocktest-list")

    def test_func(self):
        # Ensure only the owner can delete
        mock_test = self.get_object()
        return self.request.user == mock_test.user


from django.core.paginator import Paginator


def MockTest_user(request):
    # Retrieve all MockTest instances
    mocktests = MockTest.objects.all()

    # Get the first AdSenseConfig instance (assuming only one config exists)
    ads_config = AdSenseConfig.objects.first()

    # Pagination (optional, if you have many mock tests)
    paginator = Paginator(mocktests, 10)  # Show 10 mock tests per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    context = {
        "ads_config": ads_config,
        "mocktests": page_obj,  # Use paginated mocktests
    }

    return render(request, "mocktest/mock_test_user.html", context)


@login_required()
def instructions_view(request, mocktest_id):
    mocktest = get_object_or_404(MockTest, id=mocktest_id)
    context = {
        "mocktest": mocktest,  # MockTest object, which might include details like Exam Name, Instructions, etc.
        "duration": mocktest.duration,  # Duration of the mock test
    }
    return render(request, "mocktest/instructions.html", context)


@login_required()
def mocktest_detailview(request, mocktest_id):
    logger.debug(f"Fetching MockTest with ID: {mocktest_id}")

    try:
        # Get MockTest object
        mocktest = get_object_or_404(MockTest, id=mocktest_id)
        logger.debug(f"MockTest found: {mocktest}")
    except Exception as e:
        logger.error(f"Error fetching MockTest with ID {mocktest_id}: {e}")
        raise

    # Fetch the test duration
    test_duration = int(mocktest.duration.total_seconds() // 60)
    # test_duration = mocktest.duration
    logger.debug(f"Test duration: {test_duration}")

    # Get subject configurations for this mock test
    try:
        subject_configs = (
            mocktest.subject_configs.all()
        )  # Assuming MockTest has related field subject_configs
        logger.debug(f"Fetched {len(subject_configs)} subject configurations.")
    except Exception as e:
        logger.error(f"Error fetching subject configurations: {e}")
        raise

    questions = []
    total_questions = 0

    # Loop through each subject configuration and fetch random questions
    logger.debug(f"Fetching random questions based on subject configurations.")
    for config in subject_configs:
        try:
            # Fetch random questions for each subject based on num_questions
            subject_questions = Questions.objects.filter(
                Subject=config.subject
            ).order_by("?")[: config.num_questions]
            logger.debug(
                f"Fetched {len(subject_questions)} random questions for subject {config.subject}."
            )

            questions.extend(subject_questions)
            total_questions += config.num_questions
        except Exception as e:
            logger.error(f"Error fetching questions for subject {config.subject}: {e}")
            continue  # Continue processing other subjects even if one fails

    logger.debug(f"Total questions fetched: {total_questions}")

    # Save the questions in session to be available when submitting
    logger.debug("Saving questions in session for later use.")
    request.session["mocktest_questions"] = [
        {"id": question.id, "question": question.question} for question in questions
    ]

    if request.method == "POST":
        logger.debug(
            "POST request received, redirecting to test_submit with questions."
        )
        return test_submit(request, mocktest, questions)  # Passing questions explicitly

    logger.debug("Rendering mocktest detail view.")
    return render(
        request,
        "mocktest/mocktest_detail.html",
        {
            "mocktest": mocktest,
            "questions": questions,
            "test_duration": test_duration,
            "total_questions": total_questions,  # Pass total number of questions to template
        },
    )


def test_submit(request, mocktest_id):
    if request.method == "POST":
        # Retrieve session questions data
        questions_data = request.session.get("mocktest_questions", [])
        if not questions_data:
            logger.error("No question data found in session.")
            return redirect("mocktest-user")

        # Retrieve mock test instance
        mocktest = get_object_or_404(MockTest, id=mocktest_id)
        logger.debug(f"Mock test retrieved: {mocktest.Exam_Name}")

        # Generate a unique UUID for this submission
        submission_uuid = uuid.uuid4()
        logger.debug(f"Generated submission UUID: {submission_uuid}")

        # Process user responses
        for question_data in questions_data:
            question_id = question_data.get("id")
            correct_answer = question_data.get(
                "correct_answer"
            )  # Use .get() to avoid KeyError
            explanation = question_data.get("explanation")
            logger.debug(f"Processing question ID: {question_id}")

            if correct_answer is None:
                # If the correct answer is missing, fetch it from the database
                question = get_object_or_404(Questions, id=question_id)
                correct_answer = question.answer
                logger.debug(
                    f"Fetched correct_answer from the database for question {question.id}"
                )

            explanation = question_data.get("explanation")
            # Check if correct_answer is missing
            if correct_answer is None:
                logger.error(
                    f"Correct answer is missing for question {question_id}. Skipping this question."
                )
                continue  # Skip this question if the correct answer is missing

            # Process the response
            selected_option = int(request.POST.get(f"question_{question_id}", 0))
            is_correct = selected_option == correct_answer
            answer_description = question_data.get(
                f"option_{selected_option}", "Invalid selection."
            )
            logger.debug(
                f"User selected option {selected_option}, is_correct: {is_correct}"
            )

            # Save user response
            UserResponse.objects.update_or_create(
                user=request.user,
                mock_test=mocktest,
                question_id=question_id,
                submission_id=submission_uuid,
                defaults={
                    "selected_option": selected_option,
                    "correct_answer": correct_answer,
                    "is_correct": is_correct,
                    "answer_description": answer_description,
                    "explanation": explanation,
                    "exam_name": mocktest.Exam_Name,
                },
            )
            logger.debug(f"Saved response for question ID: {question_id}")

        # Clear session questions after submission
        del request.session["mocktest_questions"]
        logger.debug("Cleared mocktest_questions from session.")

        # Redirect to the results page with the submission UUID
        logger.debug(
            f"Redirecting to results page with submission UUID: {submission_uuid}"
        )
        return redirect(
            "mocktest_result", mocktest_id=mocktest.id, submission_uuid=submission_uuid
        )

    # Handle case when method is not POST (should not happen in this flow)
    logger.error("Request method is not POST.")
    return redirect("mocktest-user")


def test_result(request, mocktest_id, submission_uuid):
    # Retrieve mock test instance
    mocktest = get_object_or_404(MockTest, id=mocktest_id)

    # Fetch user responses linked to the current submission (filtered by submission_id)
    user_responses = UserResponse.objects.filter(
        user=request.user,
        mock_test=mocktest,
        submission_id=submission_uuid,  # Use submission_uuid to filter responses
    )

    # Attempted responses for score calculation
    attempted_responses = user_responses.exclude(is_correct=None)

    # Calculate correct and incorrect answers
    correct_count = attempted_responses.filter(is_correct=True).count()
    incorrect_count = attempted_responses.filter(is_correct=False).count()

    # Calculate the score by subtracting 1/3 for each incorrect answer
    score = round((correct_count - mocktest.negative_mark * incorrect_count), 2)
    percentage_score = (
        round((score / mocktest.total_max_score) * 100, 2)
        if mocktest.total_max_score > 0
        else 0
    )
    # Determine badge type based on score

    if percentage_score >= 90:
        badge_type = "Gold"
    elif percentage_score >= 75:
        badge_type = "Silver"
    elif percentage_score >= 60:
        badge_type = "Bronze"
    else:
        badge_type = "No Badge"

    # Identify unattempted questions
    attempted_ids = user_responses.values_list("question_id", flat=True)
    unattempted_questions = [
        q
        for q in request.session.get("mocktest_questions", [])
        if q["id"] not in attempted_ids
    ]

    # Calculate total questions (attempted + unattempted)
    total_question = len(attempted_responses) + len(unattempted_questions)

    # Save or update user response
    Badge.objects.update_or_create(
        user=request.user,
        submission_id=submission_uuid,
        mock_test=mocktest,
        defaults={
            "score": score,
            "attempted_question": len(attempted_responses),
            "total_question": total_question,
            "Incorrect_question": incorrect_count,
            "unattempted_questions": len(unattempted_questions),
            "badge_type": badge_type,
            "exam_name": mocktest.Exam_Name,
        },
    )

    logger.debug(f"Saved response for submission id: {submission_uuid}")

    # Return the results to the template
    return render(
        request,
        "mocktest/test_result.html",
        {
            "mocktest": mocktest,
            "responses": user_responses,
            "correct_count": correct_count,
            "unattempted_questions": unattempted_questions,
            "exam_name": mocktest.Exam_Name,
            "score": score,
            "badge_type": badge_type,
            "percentage_score": percentage_score,
        },
    )


def subject_list(request):
    """
    View to display subjects filtered by selected category.
    """
    categories = Subjectcatogary.objects.all()
    selected_category_id = request.GET.get("category")  # Get selected category from URL parameters

    if selected_category_id:
        subjects = Subject.objects.filter(Subjectcatogary_id=selected_category_id, is_active=True)
    else:
        subjects = Subject.objects.filter(is_active=True)  # Show all if no category is selected

    context = {
        "categories": categories,
        "subjects": subjects,
        "selected_category_id": int(selected_category_id) if selected_category_id else None,
    }
    return render(request, "subject/subject_user.html", context)



def subject_detail(request, pk):
    """
    View to display the details of a subject and its units/topics.
    """
    subject = get_object_or_404(Subject, pk=pk)
    units = subject.units.prefetch_related("topics")  # Fetch units and related topics
    selected_topic = None

    # Check if a topic is selected
    topic_id = request.GET.get("topic_id")
    if topic_id:
        selected_topic = get_object_or_404(Topic, pk=topic_id, subject=subject)

    context = {
        "subject": subject,
        "units": units,
        "selected_topic": selected_topic,
    }
    return render(request, "subject/subject_detail.html", context)


# Fetch current affairs
import os
import requests
from dotenv import load_dotenv

load_dotenv()

def fetch_current_affairs():
    API_KEY = os.getenv("NEWS_API_KEY_FOR_CURRENTS")
    url = f"https://api.currentsapi.services/v1/latest-news?apiKey={API_KEY}&country=in&language=hi"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        articles = data.get("news", [])
        headlines = [
            {"title": article["title"], "url": article["url"]}
            for article in articles[:20]
        ]
        return headlines
    else:
        print(f"Error fetching news: {response.status_code}, {response.text}")
        return []
"""

# views.py
import os
import requests
from dateutil import parser  # Import the dateutil parser
from django.http import JsonResponse
from core.models import News


def fetch_current_affairs(request):
    API_KEY = os.getenv("NEWS_API_KEY_FOR_CURRENTS")
    url = f"https://api.currentsapi.services/v1/latest-news?apiKey={API_KEY}&country=in&language=hi"

    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        articles = data.get("news", [])

        # Loop through the first 50 articles
        for article in articles[:50]:
            title = article.get("title", "No title")
            url = article.get("url", "#")
            description = article.get("description", "No description")
            published_at_str = article.get("published", None)

            # Ensure published_at_str is not None or empty before parsing
            if published_at_str:
                published_at = parser.parse(published_at_str)
            else:
                published_at = None

            author = article.get("author", "Unknown")
            source = article.get("source", "Unknown")
            country = article.get("country", "No title")
            language = article.get("language", "No title")
            category = article.get("category", "No title")

            # Save to database
            News.objects.create(
                title=title,
                url=url,
                description=description,
                published_at=published_at,
                author=author,
                language=language,
                state=None,  # You can update this if state data is available
                country=country,
                source=source,
                category=category,
            )

        return JsonResponse({'status': 'success', 'message': f"Successfully saved {len(articles[:50])} news articles."})

    else:
        return JsonResponse(
            {'status': 'error', 'message': f"Error fetching news: {response.status_code}, {response.text}"})
"""

# View to display current affairs
def CurrentAffaires(request):
    current_affairs = fetch_current_affairs()
    return render(request, "news.html", {"current_affairs": current_affairs})


from rest_framework import viewsets
from .models import Advertisement, Job, JobType, JobCategory, JobStage
from .serializers import (
    AdvertisementSerializer,
    JobSerializer,
    JobTypeSerializer,
    JobCategorySerializer,
    JobStageSerializer,
)


class AdvertisementViewSet(viewsets.ModelViewSet):
    queryset = Advertisement.objects.all()
    serializer_class = AdvertisementSerializer


class JobTypeViewSet(viewsets.ModelViewSet):
    queryset = JobType.objects.all()
    serializer_class = JobTypeSerializer


class JobCategoryViewSet(viewsets.ModelViewSet):
    queryset = JobCategory.objects.all()
    serializer_class = JobCategorySerializer


class JobStageViewSet(viewsets.ModelViewSet):
    queryset = JobStage.objects.all()
    serializer_class = JobStageSerializer


class JobViewSet(viewsets.ModelViewSet):
    queryset = Job.objects.all()
    serializer_class = JobSerializer


class SavedJobViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing saved jobs.
    """

    queryset = SavedJob.objects.all()
    serializer_class = SavedJobSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        """
        Filter saved jobs to only show those saved by the currently authenticated user.
        """
        return SavedJob.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        """
        Automatically associate the saved job with the currently authenticated user.
        """
        serializer.save(user=self.request.user)


from django.core.paginator import Paginator
from django.shortcuts import render
from .models import Job, JobType, JobStage


def sarkari_jobs(request):
    sarkari_type = JobType.objects.get(name="Sarkari")
    jobs = Job.objects.filter(job_type=sarkari_type).order_by("-created_at")

    # Assuming you have a JobStage model and it has a 'name' or similar field to identify stages
    admit_card_stage = JobStage.objects.get(name="Admit Card Released")
    result_declared_stage = JobStage.objects.get(name="Result Declared")

    # Filter jobs by specific stages
    admit_card_jobs = jobs.filter(stage=admit_card_stage)
    result_declared_jobs = jobs.filter(stage=result_declared_stage)
    other_jobs = jobs.exclude(stage__in=[admit_card_stage, result_declared_stage])

    # Pagination for the other jobs
    paginator = Paginator(other_jobs, 20)  # 20 jobs per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)

    return render(
        request,
        "jobs/sarkari_jobs.html",
        {
            "page_obj": page_obj,
            "admit_card_jobs": admit_card_jobs,
            "result_declared_jobs": result_declared_jobs,
        },
    )


def private_jobs(request):
    """
    View to display Private jobs.
    """
    private_type = JobType.objects.get(name="Private")
    jobs = Job.objects.filter(job_type=private_type).order_by("-created_at")
    paginator = Paginator(jobs, 20)  # 20 jobs per page
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, "jobs/private_jobs.html", {"page_obj": page_obj})


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.utils.timezone import now
from .models import Job, SavedJob, Advertisement


def job_detail_view(request, pk):
    # Fetch job details or return a 404 if not found
    job_details = get_object_or_404(Job, pk=pk)
    ads_config = AdSenseConfig.objects.first()
    # Fetch active advertisements
    active_ads = Advertisement.objects.filter(is_active=True, expiry_date__gte=now())

    # Handle job save functionality
    if request.method == "POST" and "save_job" in request.POST:
        job_link = request.build_absolute_uri()  # Generate full URL for the job
        exam_name = request.GET.get(
            "exam_name", "others"
        )  # Default to 'others' if not provided
        SavedJob.objects.get_or_create(
            user=request.user, job_link=job_link, defaults={"exam_name": exam_name}
        )

        return redirect("job_detail", pk=pk)

    # Context for rendering the template
    context = {
        "job_details": job_details,
        "active_ads": active_ads,
        "ads_config": ads_config,
    }

    return render(request, "jobs/job_detail.html", context)


# List and Create API View


class ExperienceLevelViewSet(viewsets.ModelViewSet):
    queryset = ExperienceLevel.objects.all()
    serializer_class = ExperienceLevelSerializer


class CartViewSet(viewsets.ModelViewSet):
    queryset = Cart.objects.all()
    serializer_class = CartSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Cart.objects.filter(user=user)

    @action(detail=True, methods=["post"])
    def update_quantity(self, request, pk=None):
        cart_item = self.get_object()
        quantity = request.data.get("quantity", 1)
        cart_item.quantity = quantity
        cart_item.save()
        return Response(CartSerializer(cart_item).data)


class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user = self.request.user
        return Order.objects.filter(user=user)

    @action(detail=True, methods=["post"])
    def complete_order(self, request, pk=None):
        order = self.get_object()
        # Assuming payment completion logic here
        order.total_amount = sum(
            [
                cart_item.total_price()
                for cart_item in Cart.objects.filter(user=request.user)
            ]
        )
        order.save()
        return Response(OrderSerializer(order).data)


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Cart, Order

from django.utils.timezone import now
from django.db import transaction


@login_required
def add_to_cart(request, item_type, item_id):
    """
    Add an item (course or test) to the cart.
    """
    if item_type == "course":
        model = Course
    elif item_type == "test":
        model = MockTest
    else:
        return JsonResponse({"error": "Invalid item type"}, status=400)

    item = get_object_or_404(model, id=item_id)

    cart_item, created = Cart.objects.get_or_create(
        user=request.user,
        product_id=item.id,
        product_type=ContentType.objects.get_for_model(model),
        defaults={"quantity": 1},
    )

    if not created:
        cart_item.quantity += 1
        cart_item.save()

    return redirect("view_cart")


@login_required
def view_cart(request):
    """
    Display the cart with all items.
    """
    cart_items = Cart.objects.filter(user=request.user)
    total_price = sum(item.total_price() for item in cart_items)
    return render(
        request,
        "order/view_cart.html",
        {"cart_items": cart_items, "total_price": total_price},
    )


@login_required
@transaction.atomic
def checkout(request):
    """
    Checkout view to handle payment processing and order status updates.
    """
    cart_items = Cart.objects.filter(user=request.user)

    if not cart_items:
        return redirect("view_cart")

    total_price = sum(item.total_price() for item in cart_items)
    if request.method == "POST":
        # Create a new order and set the initial status
        order = Order.objects.create(
            user=request.user,
            total_amount=total_price,
            order_status="Payment Initiated",
        )

        # Update order status to "Payment Completed" after successful payment
        order.order_status = "Payment Completed"
        order.save()

        # Clear the cart after successful payment
        cart_items.delete()

        return redirect("payment_success", order_id=order.id)

    return render(
        request,
        "order/checkout.html",
        {"cart_items": cart_items, "total_price": total_price},
    )


@login_required
def payment(request, order_id):
    """
    Handle payment for a specific order.
    """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if request.method == "POST":
        # Simulate payment completion
        order.order_status = "Payment Confirmed"
        order.payment_status = "Completed"
        order.save()
        return redirect("payment_success", order_id=order.id)

    return render(request, "order/payment.html", {"order": order})


@login_required
def payment_success(request, order_id):
    """
    Display payment success page and update order validity.
    """
    order = get_object_or_404(Order, id=order_id, user=request.user)

    if order and not order.valid_until:
        order.valid_until = now() + timedelta(days=365)
        order.save()

    return render(request, "order/payment_success.html", {"order": order})


from rest_framework.exceptions import NotFound
from .models import CurrentAffair
from .serializers import CurrentAffairSerializer


class CurrentAffairAPIView(APIView):
    """
    API for managing Current Affairs - supports create, retrieve, update, delete, and list.
    """

    def get_object(self, pk):
        try:
            return CurrentAffair.objects.get(pk=pk)
        except CurrentAffair.DoesNotExist:
            raise NotFound(detail="Current Affair not found.")

    def get(self, request, pk=None):
        """
        Retrieve a single Current Affair by ID or list all Current Affairs.
        """
        if pk:
            current_affair = self.get_object(pk)
            serializer = CurrentAffairSerializer(current_affair)
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
            current_affairs = CurrentAffair.objects.all()
            serializer = CurrentAffairSerializer(current_affairs, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        """
        Create a new Current Affair.
        """
        serializer = CurrentAffairSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, pk=None):
        """
        Update an existing Current Affair.
        """
        if not pk:
            return Response(
                {"detail": "ID is required for updating a record."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        current_affair = self.get_object(pk)
        serializer = CurrentAffairSerializer(current_affair, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk=None):
        """
        Delete a Current Affair by ID.
        """
        if not pk:
            return Response(
                {"detail": "ID is required for deleting a record."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        current_affair = self.get_object(pk)
        current_affair.delete()
        return Response(
            {"detail": "Current Affair deleted successfully."},
            status=status.HTTP_204_NO_CONTENT,
        )


from django.shortcuts import render
from django.db.models import Q
from datetime import datetime, timedelta
from .models import CurrentAffair


def current_affairs_list(request):
    """
    View to display the list of current affairs with filters for date range, category, and country.
    """
    search_query = request.GET.get("search", "")
    category = request.GET.get("category", "")
    country = request.GET.get("country", "")
    date_filter = request.GET.get("date_filter", "all")  # Default to 'all'
    ads_config = AdSenseConfig.objects.first()

    # Base queryset
    affairs = CurrentAffair.objects.all()

    # Apply search filter
    if search_query:
        affairs = affairs.filter(
            Q(title__icontains=search_query) | Q(country__icontains=search_query)
        )

    # Apply category filter
    if category:
        affairs = affairs.filter(category__id=category)

    # Apply country filter
    if country:
        affairs = affairs.filter(country__icontains=country)

    # Apply date filter
    today = datetime.now().date()
    if date_filter == "current_week":
        start_of_week = today - timedelta(days=today.weekday())
        affairs = affairs.filter(date__gte=start_of_week, date__lte=today)
    elif date_filter == "current_month":
        affairs = affairs.filter(date__year=today.year, date__month=today.month)
    elif date_filter == "current_year":
        affairs = affairs.filter(date__year=today.year)
    elif date_filter == "previous_years":
        affairs = affairs.filter(date__lt=datetime(today.year, 1, 1).date())

    # Paginate results
    paginator = Paginator(affairs, 10)  # Show 10 results per page
    page_number = request.GET.get("page")
    current_affairs = paginator.get_page(page_number)

    context = {
        "ads_config": ads_config,
        "current_affairs": current_affairs,
        "search_query": search_query,
        "category": category,
        "country": country,
        "date_filter": date_filter,
        "categories": AffairsCategory.objects.all(),  # Pass categories for dropdown
        "countries": CurrentAffair.objects.values_list(
            "country", flat=True
        ).distinct(),  # Unique countries
    }
    return render(request, "current_affairs_list.html", context)


class AffairsCategoryViewSet(viewsets.ModelViewSet):
    queryset = AffairsCategory.objects.all()
    serializer_class = AffairsCategorySerializer


from django.contrib.auth.decorators import login_required
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from .models import SavedJob, Cart, Order, Badge, UserResponse, QuizResult


@login_required
def user_dashboard(request):
    # Fetch data for the logged-in user
    user = request.user
    saved_jobs = SavedJob.objects.filter(user=user)
    cart_items = Cart.objects.filter(user=user)
    orders = Order.objects.filter(user=user)
    badges = Badge.objects.filter(user=user)
    user_responses = UserResponse.objects.filter(user=user)
    quiz_results = QuizResult.objects.filter(user=user)

    # Prepare context to pass to the template
    context = {
        "user": user,  # Directly passing the logged-in user
        "saved_jobs": saved_jobs,
        "cart_items": cart_items,
        "orders": orders,
        "badges": badges,
        "user_responses": user_responses,
        "quiz_results": quiz_results,
    }

    return render(request, "user/user_dashboard.html", context)


from django.utils.translation import activate


def set_language(request):
    if request.method == 'POST':
        lang_code = request.POST.get('language')
        request.session['django_language'] = lang_code
    return redirect(request.META.get('HTTP_REFERER', '/'))


@api_view(["POST"])
@parser_classes([MultiPartParser, FormParser])
@permission_classes([AllowAny])
def upload_questions(request):
    """API endpoint to upload questions in bulk via an Excel file with detailed logging."""

    logger.debug("Received a request to upload questions.")
    logger.info(f"Request method: {request.method}, User: {request.user}")

    # Check if file is provided
    file = request.FILES.get("file")
    if not file:
        logger.error("No file provided in the request.")
        return Response(
            {"error": "No file provided"}, status=status.HTTP_400_BAD_REQUEST
        )

    try:
        logger.debug(f"Received file: {file.name}, Size: {file.size} bytes")
        logger.debug("Reading Excel file.")
        df = pd.read_excel(file, engine="openpyxl")

        for index, row in df.iterrows():
            try:
                # Example validation (modify as needed)
                if not isinstance(row['option_2'], str):  # Validate if 'option_2' is a string
                    raise ValueError(
                        f"Invalid data type for 'option_2' at row {index + 2}")  # +2 to match Excel row numbers (header included)

                # Print correct row info
                logger.debug(f"Row {index + 2} is valid: {row.to_dict()}")

            except Exception as e:
                logger.error(f"Error at row {index + 2}: {e}")
                raise  # Stop processing on error

        # Expected columns in Excel file
        required_columns = [
            "Subject",
            "question_level",
            "unit",
            "topic",
            "question",
            "option_1",
            "option_2",
            "option_3",
            "option_4",
            "answer",
            "explanation",
        ]

        logger.debug("Checking if all required columns are present in the uploaded file.")
        if not all(col in df.columns for col in required_columns):
            logger.error("Invalid file format. Missing required columns.")
            return Response(
                {
                    "error": "Invalid file format. Ensure all required columns are present."
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        questions_list = []
        logger.debug("Processing rows from the Excel file.")
        for index, row in df.iterrows():
            try:
                subject_name = row["Subject"].strip()
                logger.debug(f"Row {index + 1}: Fetching Subject: {subject_name}")
                subject = Subject.objects.get(name=subject_name)

                existing_question = Questions.objects.filter(
                    Subject=subject, question=row["question"]
                ).exists()

                if existing_question:
                    logger.warning(f"Row {index + 1}: Question already exists: {row['question']}")
                    return Response(
                        {"error": f"Question already exists: {row['question']}"},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

                question_data = {
                    "Subject": subject.id,
                    "question_level": row["question_level"].strip(),
                    "unit": row["unit"],
                    "topic": row["topic"],
                    "question": row["question"],
                    "option_1": row["option_1"],
                    "option_2": row["option_2"],
                    "option_3": row["option_3"],
                    "option_4": row["option_4"],
                    "answer": int(row["answer"]),
                    "explanation": row["explanation"]  # Truncate if too long
                }
                questions_list.append(question_data)
                logger.debug(f"Row {index + 1}: Processed question: {row['question']}")

            except Subject.DoesNotExist:
                logger.error(f"Row {index + 1}: Subject '{subject_name}' not found in database.")
                return Response(
                    {"error": f"Subject '{subject_name}' not found in database."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            except ValueError as e:
                logger.error(f"Row {index + 1}: Data error: {str(e)}")
                return Response(
                    {"error": f"Data error: {str(e)}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        logger.debug("Serializing and saving questions.")
        serializer = QuestionsSerializer(data=questions_list, many=True)
        if serializer.is_valid():
            serializer.save()
            logger.info(f"{len(questions_list)} questions uploaded successfully!")
            return Response(
                {"message": f"{len(questions_list)} questions uploaded successfully!"},
                status=status.HTTP_201_CREATED,
            )
        else:
            logger.error(f"Validation errors: {serializer.errors}")
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as e:
        logger.error(f"An error occurred: {str(e)}", exc_info=True)
        return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def upload_questions_view(request):
    """Render the Excel upload page and handle file uploads with detailed logging."""

    logger.debug("Rendering upload questions page.")
    if request.method == "POST" and request.FILES.get("file"):
        file = request.FILES["file"]
        api_url = "http://127.0.0.1:8000/upload-questions/"  # Change for production

        logger.info(f"Received file upload request: {file.name}, Size: {file.size} bytes")

        files = {"file": file}
        try:
            response = requests.post(api_url, files=files)
            logger.info(f"Sent file to API: {api_url}, Status Code: {response.status_code}")

            if response.status_code == 201:
                messages.success(request, "File uploaded successfully! ✅")
                logger.info(f"File {file.name} uploaded successfully.")
                return render(request, "dashboard.html")
            else:
                try:
                    error_message = response.json().get("error", "Something went wrong!")
                except Exception as e:
                    error_message = "Failed to parse error response from API."
                    logger.error(f"Error parsing API response: {e}")

                messages.error(request, f"Upload failed: {error_message} ❌")
                logger.error(f"File upload failed. API response: {response.text}")

        except requests.exceptions.RequestException as e:
            logger.error(f"Request to API failed: {e}", exc_info=True)
            messages.error(request, "Server connection failed. Please try again later. ❌")

    return render(request, "question/upload_questions.html")


from django.shortcuts import render, redirect
from django.contrib import messages
from .models import Topic, Questions
import random
from datetime import datetime
from django.utils import timezone

naive_datetime = datetime.now()  # This is naive
aware_datetime = timezone.make_aware(naive_datetime)  # Convert to timezone-aware


def create_questions_from_topic(request):
    logger.info("Fetching topics created in the last 30 days.")
    topics = Topic.objects.filter(created_at__gte=timezone.now() - timedelta(days=30))
    generated_questions = []  # List to store generated questions temporarily

    if request.method == "POST":
        if "generate" in request.POST:
            topic_id = request.POST.get("topic_id")
            logger.info(f"Received request to generate questions for topic ID: {topic_id}")

            try:
                topic = Topic.objects.get(id=topic_id)
                description = topic.description
                logger.info(f"Fetched topic: {topic.topic}")

                if len(description) < 1000:
                    logger.warning("Description is too short to generate questions.")
                    messages.error(request, "Description is too short to generate questions.")
                    return redirect("create_questions_from_topic")

                generated_questions = generate_questions_from_topic(topic)
                logger.info(f"Generated {len(generated_questions)} questions.")

                return render(request, "create_questions_from_topic.html",
                              {"topics": topics, "generated_questions": generated_questions})

            except Topic.DoesNotExist:
                logger.error(f"Topic with ID {topic_id} does not exist.")
                messages.error(request, "Selected topic does not exist.")
                return redirect("create_questions_from_topic")

        elif "save" in request.POST:
            logger.info("Saving generated questions to the database.")
            for question in generated_questions:
                question.save()
                logger.info(f"Saved question: {question.question}")

            messages.success(request, "Questions saved successfully!")
            return redirect("create_questions_from_topic")

    return render(request, "create_questions_from_topic.html", {"topics": topics})


def generate_questions_from_topic(topic):
    logger.info(f"Generating questions for topic: {topic.topic}")
    description = topic.description
    questions = []

    for i in range(20):  # Generate 20 questions
        question_text = f"Question {i + 1} about {topic.topic}?"
        options = [
            f"Option 1 for {topic.topic}",
            f"Option 2 for {topic.topic}",
            f"Option 3 for {topic.topic}",
            f"Option 4 for {topic.topic}",
        ]
        correct_answer = random.randint(1, 4)  # Randomly choose the correct answer (1-based index)

        question = Questions(
            Subject=topic.subject,
            question=question_text,
            option_1=options[0],
            option_2=options[1],
            option_3=options[2],
            option_4=options[3],
            answer=correct_answer,
            explanation=f"Explanation for {question_text}",
            topic=topic.description,  # You can adjust the topic representation here
        )

        questions.append(question)
        logger.info(f"Generated question: {question_text}")

    logger.info(f"Total {len(questions)} questions generated for topic: {topic.topic}")
    return questions