""".. Ignore pydocstyle D400.

========================
Contests API serializers
========================

.. autoclass:: rola.contests.api.serializers.ThemeSerializer
    :members:

.. autoclass:: rola.contests.api.serializers.ContestSerializer
    :members:

"""

from rest_framework import serializers

from rola.common.serializers import BaseSerializer
from rola.contests.models import Contest, Institution, Theme


class InstitutionSerializer(BaseSerializer):
    """Serializer for Author objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Institution
        fields = BaseSerializer.Meta.fields + ["name", "kind"]


class ThemeSerializer(BaseSerializer):
    """Serializer for Theme objects."""

    submissions_number = serializers.SerializerMethodField("get_submissions_number")

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Theme
        fields = BaseSerializer.Meta.fields + [
            "title",
            "is_series",
            "n_photos",
            "submissions_number",
        ]

    def get_submissions_number(self, theme) -> int:
        """Count submissions in this theme."""
        # Contest lists and details annotate the count. Contest write
        # responses count per theme, and theme results count the
        # submissions they have already prefetched.
        if hasattr(theme, "submission_count"):
            return theme.submission_count
        return theme.submission_set.count()


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
            "dob_required",
            "club_show",
            "club_required",
            "school_show",
            "school_required",
        ]
