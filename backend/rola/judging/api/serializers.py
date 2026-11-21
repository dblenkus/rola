"""Serialize ratings, judging lists and published results."""

from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from rola.common.serializers import BaseSerializer
from rola.contests.api.serializers import ContestSerializer as CoreContestSerializer
from rola.contests.api.serializers import ThemeSerializer as CoreThemeSerializer
from rola.entries.api.serializers import FileSerializer
from rola.entries.api.serializers import (
    SubmissionSerializer as CoreSubmissionSerializer,
)
from rola.entries.models import Author, Submission
from rola.judging.models import Rating, SubmissionReward


class RatingSerializer(BaseSerializer):
    """Serialize a judge's rating, whose submission the request path names."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Rating
        fields = BaseSerializer.Meta.fields + ["submission", "rating"]
        read_only_fields = BaseSerializer.Meta.read_only_fields + ["submission"]


class JudgeThemeSerializer(CoreThemeSerializer):
    """Serializer for Theme objects."""

    rating_count = serializers.SerializerMethodField("get_rating_count")
    # Declared again only to describe it: the parent's method reads the
    # count, which the judging queryset annotates from paid submissions.
    submission_count = serializers.SerializerMethodField(
        help_text="Count paid submissions available for judging."
    )

    class Meta(CoreThemeSerializer.Meta):
        """Serializer configuration."""

        fields = CoreThemeSerializer.Meta.fields + [
            "rating_count",
        ]

    # The judging contest queryset annotates the rating count, and the paid
    # submission count that the parent reads. Reading them directly fails
    # loudly if a queryset loses the annotations, instead of counting each
    # theme again.
    def get_rating_count(self, theme) -> int:
        """Count ratings submitted by the requesting judge."""
        return theme.rating_count


class JudgeContestSerializer(CoreContestSerializer):
    """Serializer for Contest objects."""

    themes = JudgeThemeSerializer(many=True, read_only=True)


class JudgeSubmissionSerializer(serializers.ModelSerializer):
    """Serialize a submission for judging, without its author."""

    files = FileSerializer(many=True, read_only=True)

    class Meta:
        """Serializer configuration."""

        model = Submission
        fields = ["id", "created", "modified", "theme", "title", "description", "files"]
        read_only_fields = fields


class AuthorResultsSerializer(serializers.ModelSerializer):
    """Serialize the author details that published results show to anyone."""

    reward = serializers.CharField(
        source="reward.label", read_only=True, allow_null=True
    )
    reward_theme = serializers.IntegerField(
        source="reward.theme_id", read_only=True, allow_null=True
    )
    country = serializers.SerializerMethodField("get_country")

    class Meta:
        """Serializer configuration."""

        model = Author
        fields = [
            "id",
            "first_name",
            "last_name",
            "school",
            "club",
            "reward",
            "reward_theme",
            "country",
        ]

    def get_country(self, author) -> str | None:
        """Return the optional country supplied by the host user model."""
        if not author.user or not author.user.location:
            return None

        return author.user.location.country


class SubmissionResultsSerializer(CoreSubmissionSerializer):
    """Serialize a published submission, its acceptance and its awards."""

    # The results queryset annotates ``score``, null unless accepted. An
    # accepted entry always has a total, so a score is what marks it.
    author = AuthorResultsSerializer()
    files = serializers.SerializerMethodField(
        "get_files", help_text="The photographs, or null unless accepted."
    )
    accepted = serializers.SerializerMethodField(
        "get_accepted",
        help_text="Whether the total of the ratings reaches the theme's threshold.",
    )
    reward_kind = serializers.SerializerMethodField("get_reward_kind")
    reward_label = serializers.CharField(
        source="reward.label", read_only=True, allow_null=True
    )
    score = serializers.IntegerField(
        read_only=True,
        allow_null=True,
        help_text="The total of the ratings, or null unless accepted.",
    )

    class Meta(CoreSubmissionSerializer.Meta):
        """Serializer configuration."""

        fields = CoreSubmissionSerializer.Meta.fields + [
            "accepted",
            "score",
            "reward_kind",
            "reward_label",
        ]

    def get_accepted(self, submission) -> bool:
        """Return whether the submission is accepted, that is, has a score."""
        return submission.score is not None

    @extend_schema_field(FileSerializer(many=True, allow_null=True))
    def get_files(self, submission):
        """Expose files only for accepted submissions."""
        if not self.get_accepted(submission):
            return None

        return FileSerializer(submission.files, many=True, context=self.context).data

    def get_reward_kind(self, submission) -> str | None:
        """Return the human-readable award kind when present."""
        mapping = dict(SubmissionReward.KIND_CHOICES)
        if hasattr(submission, "reward"):
            return mapping[submission.reward.kind]
        return None

    def to_representation(self, submission):
        """Publish the author's school and club only if the contest shows them."""
        data = super().to_representation(submission)
        contest = submission.theme.contest
        if not contest.school_visible:
            data["author"]["school"] = None
        if not contest.club_visible:
            data["author"]["club"] = None

        return data
