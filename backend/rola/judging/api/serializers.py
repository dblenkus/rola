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
    """Serialize published submission results and awards."""

    author = AuthorResultsSerializer()
    files = serializers.SerializerMethodField("get_files")
    accepted = serializers.SerializerMethodField("get_accepted")
    reward_kind = serializers.SerializerMethodField("get_reward_kind")
    reward_label = serializers.CharField(
        source="reward.label", read_only=True, allow_null=True
    )
    score = serializers.IntegerField(
        read_only=True,
        allow_null=True,
        help_text="The total of the submission's ratings, or null without any.",
    )

    class Meta(CoreSubmissionSerializer.Meta):
        """Serializer configuration."""

        fields = CoreSubmissionSerializer.Meta.fields + [
            "accepted",
            "score",
            "reward_kind",
            "reward_label",
        ]

    def _is_accepted(self, submission):
        if submission.score is None:
            return False

        if "accept_threshold" in self.context:
            return submission.score >= self.context["accept_threshold"]

        return submission.score >= submission.theme.results.accepted_threshold

    def get_accepted(self, submission) -> bool:
        """Report whether the submission reached the acceptance threshold."""
        return self._is_accepted(submission)

    @extend_schema_field(FileSerializer(many=True, allow_null=True))
    def get_files(self, submission):
        """Expose files only for accepted submissions."""
        if not self._is_accepted(submission):
            return None

        return FileSerializer(
            submission.files,
            many=True,
            context={
                "request": self.context["request"],
            },
        ).data

    def get_reward_kind(self, submission) -> str | None:
        """Return the human-readable award kind when present."""
        mapping = dict(SubmissionReward.KIND_CHOICES)
        if hasattr(submission, "reward"):
            return mapping[submission.reward.kind]
        return None

    def to_representation(self, submission):
        """Publish the author's school and club only if the contest shows them."""
        data = super().to_representation(submission)
        if "contest" in self.context:
            contest = self.context["contest"]
        else:
            contest = submission.theme.contest
        if not contest.school_visible:
            data["author"]["school"] = None
        if not contest.club_visible:
            data["author"]["club"] = None

        return data


class ThemeSubmissionResultsSerializer(SubmissionResultsSerializer):
    """Serialize a submission in published theme results, without its score."""

    class Meta(SubmissionResultsSerializer.Meta):
        """Serializer configuration."""

        fields = [
            field
            for field in SubmissionResultsSerializer.Meta.fields
            if field != "score"
        ]


class ThemeResultsSerializer(CoreThemeSerializer):
    """Serializer for Theme results."""

    submissions = serializers.SerializerMethodField("get_submissions")

    class Meta(CoreThemeSerializer.Meta):
        """Serializer configuration."""

        fields = CoreThemeSerializer.Meta.fields + [
            "submissions",
        ]

    def get_submission_count(self, theme) -> int:
        """Count the paid submissions in this theme."""
        # The theme results queryset prefetches the paid submissions, so
        # counting them issues no query.
        return len(theme.submission_set.all())

    @extend_schema_field(ThemeSubmissionResultsSerializer(many=True))
    def get_submissions(self, theme):
        """Serialize each submission against the theme acceptance threshold."""
        return ThemeSubmissionResultsSerializer(
            theme.submission_set.all(),
            many=True,
            context={
                "request": self.context["request"],
                "accept_threshold": theme.results.accepted_threshold,
                "contest": theme.contest,
            },
        ).data
