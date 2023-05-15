from django.contrib import admin
from .models import User_E
from .models import Salon
from .models import Employee
from .models import Service
from .models import Employee_Service
admin.site.register(User_E)
admin.site.register(Salon)
admin.site.register(Employee)
admin.site.register(Service)
admin.site.register(Employee_Service)
