from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),
    path("ckeditor/", include("ckeditor_uploader.urls")),  # CKEditor URL patterns
    path("", include("core.urls")),  # Ensure this path is correct
]
