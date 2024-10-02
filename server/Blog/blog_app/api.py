from .serializers import BlogSerializer
from .models import Blog
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticatedOrReadOnly
from account.authenticate import CustomAuthentication
from django.contrib.auth import get_user_model
User = get_user_model()

import logging
logger = logging.getLogger(__name__)

class BlogViewSets(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticatedOrReadOnly]
    authentication_classes = [CustomAuthentication]
    queryset = Blog.objects.all()
    serializer_class = BlogSerializer


    def perform_create(self, serializer):
        serializer.save()
        logger.info(f"Created object: {serializer.data}")


    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        logger.info(f"Listed objects: {response.data}")
        return response


    def get_object(self):
        obj = super().get_object()
        logger.info(f"Retrieved object: {obj}")
        return obj


    def perform_update(self, serializer):
        serializer.save()
        logger.info(f"Updated object: {serializer.data}")


    def perform_destroy(self, instance):
        logger.info(f"Deleted object: {instance}")
        instance.delete()

