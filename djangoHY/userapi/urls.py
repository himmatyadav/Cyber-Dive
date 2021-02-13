from rest_framework import routers
from .views import AuthenticateViewSet

router = routers.DefaultRouter(trailing_slash=False)
router.register('api/auth', AuthenticateViewSet, basename='auth')

urlpatterns = router.urls