

from category.models import Category
from .models import *

def menu_links(request):
    links = Category.objects.all()
    return dict(links=links)