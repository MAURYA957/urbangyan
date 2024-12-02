# your_app/templatetags/custom_filters.py
from django import template
from bs4 import BeautifulSoup

register = template.Library()

@register.filter
def truncate_html(value, max_length):
    soup = BeautifulSoup(value, 'lxml')
    text = soup.get_text()[:max_length]
    if len(soup.get_text()) > max_length:
        return f"{text}..."
    return text
