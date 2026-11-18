"""Serializers shared by the apps."""

from rest_framework import serializers


class BaseSerializer(serializers.ModelSerializer):
    """Base serializer for Rolca models."""

    user = serializers.HiddenField(
        default=serializers.CreateOnlyDefault(serializers.CurrentUserDefault())
    )

    class Meta:
        """Serializer configuration."""

        fields = ["id", "user", "created", "modified"]
        read_only_fields = ["id"]
