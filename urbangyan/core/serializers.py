from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Blog, Course, Topic, Quiz, Questions, User, UserSession, QuizName, Unit, Subject, \
    Offer, MockTestSubjectConfig, MockTest
from rest_framework import serializers
from django.contrib.auth.hashers import make_password



class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        exclude = ['groups', 'user_permissions']  # Exclude many-to-many fields

    def create(self, validated_data):
        # Hash the password before saving the user
        if 'password' in validated_data:
            validated_data['password'] = make_password(validated_data['password'])

        user = User(**validated_data)
        user.save()
        return user

    def update(self, instance, validated_data):
        # Hash the password if it's provided in the update request
        password = validated_data.pop('password', None)
        if password:
            instance.password = make_password(password)

        # Update the rest of the fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance

    def to_representation(self, instance):
        # Exclude the password field from the serialized output
        representation = super().to_representation(instance)
        representation.pop('password', None)  # Ensure password is not in the output
        return representation


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        # Add custom claims
        token['username'] = user.username
        token['first_name'] = user.first_name
        token['last_name'] = user.last_name

        return token


class BlogSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blog
        fields = '__all__'



class QuizSerializer(serializers.ModelSerializer):
    class Meta:
        model = Quiz
        fields = '__all__'


class QuestionsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Questions
        fields = '__all__'


class UserSessionSerializer(serializers.ModelSerializer):
    # Optional: Define a read-only field for the username that is derived from the user relationship
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = UserSession
        fields = ['id', 'user', 'username', 'session_key', 'logged_in_at', 'logged_out_at']
        read_only_fields = ['id', 'logged_in_at', 'username']


class OfferSerializer(serializers.ModelSerializer):
    class Meta:
        model = Offer
        fields = ['id', 'code', 'discount_percent', 'valid_from', 'valid_until', 'created_by', 'created_on']
        read_only_fields = ['created_on']

class SubjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subject
        fields = ['id', 'name', 'description', 'image', 'authors']

class CourseSerializer(serializers.ModelSerializer):
    subjects = SubjectSerializer(many=True, read_only=True)

    class Meta:
        model = Course
        fields = ['id', 'title', 'description', 'image', 'price', 'subjects']

class UnitSerializer(serializers.ModelSerializer):
    subject = SubjectSerializer(read_only=True)

    class Meta:
        model = Unit
        fields = ['id', 'subject', 'title', 'description', 'table_of_contents']

class TopicSerializer(serializers.ModelSerializer):
    course = CourseSerializer(read_only=True)

    class Meta:
        model = Topic
        fields = ['id', 'topic', 'course', 'description', 'image', 'file', 'staff', 'created_at', 'updated_at']


class MockTestSubjectConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = MockTestSubjectConfig
        fields = ['subject', 'num_questions', 'max_score']


class MockTestSerializer(serializers.ModelSerializer):
    subject_configs = MockTestSubjectConfigSerializer(many=True)
    questions = QuestionsSerializer(many=True, read_only=True)
    user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all())

    class Meta:
        model = MockTest
        fields = ['id', 'user', 'duration', 'total_questions', 'total_max_score', 'subject_configs', 'questions']

    def create(self, validated_data):
        subject_configs_data = validated_data.pop('subject_configs')
        mock_test = MockTest.objects.create(**validated_data)

        # Create related subject configs and add to mock_test
        for config_data in subject_configs_data:
            MockTestSubjectConfig.objects.create(mock_test=mock_test, **config_data)

        mock_test.populate_questions()  # Populate questions after config creation
        return mock_test