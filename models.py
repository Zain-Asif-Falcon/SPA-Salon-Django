from django.db import models
from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import models
from django.contrib.auth.validators import validators

import secrets

################################################################################################################ END_User_Database Model ################################################################

class User_E(models.Model):
    phone_number = models.CharField(max_length=50, unique=True)
    password = models.CharField(max_length=255, validators=[validators.MinLengthValidator(8)])
    name = models.CharField(max_length=255, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    address = models.CharField(max_length=255, null=True, blank=True)
    about= models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=255, null=True, blank=True)
    id = models.AutoField(primary_key=True)
    random_string = models.CharField(max_length=20, default='')
    pic_path = models.CharField(max_length=255, null=True, blank=True)

    def save(self, *args, **kwargs):
        if not self.random_string:
            self.random_string = secrets.token_hex(10) 
        super(User_E, self).save(*args, **kwargs)



class Image(models.Model):
    image = models.ImageField(upload_to='images/')
    created_at = models.DateTimeField(auto_now_add=True)
    



class Salon(models.Model):
    SID = models.AutoField(primary_key=True)
    s_name = models.CharField(max_length=255)
    address = models.CharField(max_length=255)
    city = models.CharField(max_length=255)
    open_timming = models.TimeField()
    close_timming = models.TimeField()
    image_path= models.CharField(max_length=255)
    rating = models.PositiveSmallIntegerField(
    validators=[MinValueValidator(1), MaxValueValidator(5)]
)
    


class favorite_rating():
    SID=models.CharField(max_length=255)
    user_id=models.CharField(max_length=255)
    rating = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(5)])
    


class favorite_rating():
    SID=models.CharField(max_length=255)
    user_id=models.CharField(max_length=255)
    entry = models.BooleanField(default=False)




class Employee(models.Model):
    EID = models.AutoField(primary_key=True)
    E_name = models.CharField(max_length=255)
    A_timming = models.TimeField()
    D_timming = models.TimeField()
    Expertise=models.CharField(max_length=255)
    

class Service(models.Model):
    ESID=models.AutoField(primary_key=True)
    Service=models.CharField( max_length=50)


class Employee_Service(models.Model):
    EID=models.CharField( max_length=50)
    SID=models.CharField( max_length=50)
    ID = models.AutoField(primary_key=True)
    rates=models.CharField( max_length=250)




