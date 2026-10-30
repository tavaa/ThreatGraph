from django.urls import include, path
from rest_framework.routers import DefaultRouter

from . import api_views as V

router = DefaultRouter()
router.register("vulnerabilities", V.VulnerabilityViewSet, basename="api-vulnerability")
router.register("techniques", V.TechniqueViewSet, basename="api-technique")
router.register("tactics", V.TacticViewSet, basename="api-tactic")
router.register("cwes", V.CweViewSet, basename="api-cwe")

urlpatterns = [
    path("dataset/", V.dataset, name="api-dataset"),
    path("context/", V.context, name="api-context"),
    path("", include(router.urls)),
]
