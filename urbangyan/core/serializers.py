from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import Blog, Course, Topic, Quiz, Questions, User, UserSession, Unit, Subject, \
    Offer, MockTestSubjectConfig, MockTest, SavedJob, ExperienceLevel, Order, Cart
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


from rest_framework import serializers
from .models import Advertisement, Job, JobType, JobCategory, JobStage

class AdvertisementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Advertisement
        fields = '__all__'

class JobTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobType
        fields = '__all__'

class JobCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = JobCategory
        fields = '__all__'

class JobStageSerializer(serializers.ModelSerializer):
    class Meta:
        model = JobStage
        fields = '__all__'

class JobSerializer(serializers.ModelSerializer):
    job_type = JobTypeSerializer()
    job_category = JobCategorySerializer()
    stage = JobStageSerializer()

    class Meta:
        model = Job
        fields = '__all__'


class SavedJobSerializer(serializers.ModelSerializer):
    class Meta:
        model = SavedJob
        fields = '__all__'
        read_only_fields = ('created_at',)

class ExperienceLevelSerializer(serializers.ModelSerializer):
    class Meta:
        model = ExperienceLevel
        fields = ['id', 'level', 'created_at', 'updated_at']


class CartSerializer(serializers.ModelSerializer):
    product_name = serializers.CharField(source='product.name', read_only=True)
    product_price = serializers.DecimalField(source='product.price', read_only=True, max_digits=10, decimal_places=2)

    class Meta:
        model = Cart
        fields = ['id', 'user', 'product_type', 'product_id', 'quantity', 'total_price', 'product_name',
                  'product_price']

    def create(self, validated_data):
        # Ensure that the Cart is created with the product and quantity
        return Cart.objects.create(**validated_data)


class OrderSerializer(serializers.ModelSerializer):
    user = serializers.StringRelatedField()
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    updated_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S")
    valid_until = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", required=False)

    class Meta:
        model = Order
        fields = ['id', 'user', 'total_amount', 'created_at', 'updated_at', 'valid_until']

    def create(self, validated_data):
        # Automatically set the valid_until date to 1 year after creation
        order = Order(**validated_data)
        order.save()
        return order