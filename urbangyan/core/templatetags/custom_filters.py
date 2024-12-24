# your_app/templatetags/custom_filters.py
from django import template
from bs4 import BeautifulSoup
import re

register = template.Library()

@register.filter
def truncate_html(value, max_length):
    soup = BeautifulSoup(value, 'lxml')
    text = soup.get_text()[:max_length]
    if len(soup.get_text()) > max_length:
        return f"{text}..."
    return text


@register.filter
def clean_text(value):
    """Removes HTML tags, line breaks, and extra whitespace from text."""
    if not value:
        return ""
    value = re.sub(r'\s+', ' ', value)  # Replace all whitespace (including newlines) with a single space
    return value.strip()