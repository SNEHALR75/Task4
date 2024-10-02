from rest_framework import serializers
from django.core.exceptions import ValidationError


from django.contrib.auth import get_user_model

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
	
	class Meta:
		model = User
		fields = ('id','username','password','email','is_superuser')

	def create(self,validated_data):
		return User.objects.create_user(**validated_data)

