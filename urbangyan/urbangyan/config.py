import os



SUPERUSER = {
    'username': 'Triveni',
    'password': 'tri123VENI!@#',
    'email': 'triveni@example.com',
}

NAVBAR = {
    'enable_blog_menu': True,
    'enable_course_menu': True,
}


class Config:
    # Server settings
    IP_ADDRESS = '127.0.0.1'
    PORT = 8000

    # Frontend settings
    SHOW_NAVBAR = True  # Toggle for showing the navbar

    # Additional environment variables
    DEBUG = True
    ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

    # JWT settings (in minutes)
    JWT_ACCESS_TOKEN_LIFETIME = 60  # 1 hour
    JWT_REFRESH_TOKEN_LIFETIME = 24 * 60  # 1 day

    # Static and media file paths
    STATIC_URL = '/static/'
    MEDIA_URL = '/media/'

    # PostgreSQL database settings
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'urbangyan',  # Replace with your actual database name
            'USER': 'postgres',  # Replace with your actual database username
            'PASSWORD': os.getenv('DB_PASSWORD', 'tri123VENI!@#'),  # Default database password
            'HOST': '127.0.0.1',  # Set to 'localhost' if the DB is on the same machine
            'PORT': '5432',  # Default PostgreSQL port
        }
    }