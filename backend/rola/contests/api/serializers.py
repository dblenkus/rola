"""Serialize contests, themes and institutions."""

from rola.common.serializers import BaseSerializer
from rola.contests.models import Contest, Institution, Theme


class InstitutionSerializer(BaseSerializer):
    """Serializer for Institution objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Institution
        fields = BaseSerializer.Meta.fields + ["name", "kind"]


class ThemeSerializer(BaseSerializer):
    """Serializer for Theme objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Theme
        fields = BaseSerializer.Meta.fields + [
            "title",
            "is_series",
            "max_photos",
        ]


class ContestSerializer(BaseSerializer):
    """Serializer for Contest objects."""

    themes = ThemeSerializer(many=True, read_only=True)

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Contest
        fields = BaseSerializer.Meta.fields + [
            "title",
            "description",
            "start_date",
            "end_date",
            "themes",
            "header_image",
            "notice_html",
            "confirmation_html",
            "date_of_birth_required",
            "club_visible",
            "club_required",
            "school_visible",
            "school_required",
        ]
