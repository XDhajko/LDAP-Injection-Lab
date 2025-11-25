from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),

    # Settings
    path("settings/ui/", views.settings_ui, name="settings_ui"),
    path("settings/", views.update_settings, name="update_settings"),

    # Exercises
    path("e01/login/", views.e01_login, name="e01_login"),

    path("e02/files/", views.e02_file_browser, name="e02_file_browser"),
    path("e02/download/", views.e02_download, name="e02_download"),

    path("e03/devices/", views.e03_devices, name="e03_devices"),
    path("e03/device/", views.e03_device_detail, name="e03_device_detail"),
    path("e03/workstations/", views.e03_workstations, name="e03_workstations"),

    path("e04/blind-and/", views.e04_blind_and, name="e04_blind_and"),

    path("e05/blind-or/", views.e05_blind_or, name="e05_blind_or"),
]
