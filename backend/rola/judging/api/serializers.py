"""Serialize ratings, judging lists and published results."""

from drf_spectacular.utils import extend_schema_field
from rest_framework import exceptions, serializers

from rola.common.serializers import BaseSerializer
from rola.contests.api.serializers import ContestSerializer as CoreContestSerializer
from rola.contests.api.serializers import ThemeSerializer as CoreThemeSerializer
from rola.contests.models import Contest
from rola.entries.api.serializers import FileSerializer
from rola.entries.api.serializers import (
    SubmissionSerializer as CoreSubmissionSerializer,
)
from rola.entries.models import Author, Submission
from rola.judging.models import Judge, Rating, SubmissionReward


class RatingSerializer(BaseSerializer):
    """Serializer for Rating objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Rating
        fields = BaseSerializer.Meta.fields + ["submission", "rating"]

    def create(self, validated_data):
        """Create or replace the requesting judge's score."""
        submission = validated_data.pop("submission")
        try:
            user = self.context["request"].user
            judge = Judge.objects.get(judge=user, contest=submission.theme.contest)
        except Judge.DoesNotExist:
            raise exceptions.NotAuthenticated(
                "You don't have permission to rate this contest."
            ) from None

        rating, _ = Rating.objects.update_or_create(
            submission=submission, judge=judge, defaults=validated_data
        )

        return rating

    def validate(self, attrs):
        """Keep a rating tied to its original, paid submission and active judge."""
        submission = attrs.get(
            "submission", self.instance.submission if self.instance else None
        )
        if self.instance and submission.pk != self.instance.submission_id:
            raise serializers.ValidationError(
                {"submission": "The submission cannot be changed."}
            )
        if (
            submission
            and not Judge.objects.filter(
                judge=self.context["request"].user,
                contest=submission.theme.contest,
                contest__in=Contest.objects.results_unpublished(),
            ).exists()
        ):
            raise serializers.ValidationError(
                "Only active judges can rate this contest."
            )
        # The judging list shows paid submissions only. Checked after the judge,
        # so other accounts cannot probe whether a submission is paid.
        if (
            submission
            and not Submission.objects.filter(
                pk=submission.pk, submissionset__payment__paid=True
            ).exists()
        ):
            raise serializers.ValidationError(
                {"submission": "Only paid submissions can be rated."}
            )
        return attrs


class JudgeThemeSerializer(CoreThemeSerializer):
    """Serializer for Theme objects."""

    ratings_number = serializers.SerializerMethodField("get_ratings_number")
    submissions_number = serializers.SerializerMethodField("get_submissions_number")

    class Meta(CoreThemeSerializer.Meta):
        """Serializer configuration."""

        fields = CoreThemeSerializer.Meta.fields + [
            "ratings_number",
        ]

    # The judging contest queryset annotates both counts. Reading them
    # directly fails loudly if a queryset loses the annotations, instead of
    # counting each theme again.
    def get_ratings_number(self, theme) -> int:
        """Count ratings submitted by the requesting judge."""
        return theme.rating_count

    def get_submissions_number(self, theme) -> int:
        """Count paid submissions available for judging."""
        return theme.submission_count


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

    accepted = serializers.SerializerMethodField("get_accepted")
    reward_kind = serializers.SerializerMethodField("get_reward_kind")
    reward_label = serializers.CharField(
        source="reward.label", read_only=True, allow_null=True
    )
    rating = serializers.IntegerField(
        source="rating_sum", read_only=True, allow_null=True
    )

    class Meta(CoreSubmissionSerializer.Meta):
        """Serializer configuration."""

        fields = CoreSubmissionSerializer.Meta.fields + [
            "accepted",
            "rating",
            "reward_kind",
            "reward_label",
        ]

    def get_fields(self):
        """Include result-specific author and file representations."""
        fields = super().get_fields()
        # The parent's get_fields replaces these, so class attributes have no effect.
        fields["files"] = serializers.SerializerMethodField("get_files")
        fields["author"] = AuthorResultsSerializer()

        return fields

    def _is_accepted(self, submission):
        if submission.rating_sum is None:
            return False

        if "accept_threshold" in self.context:
            return submission.rating_sum >= self.context["accept_threshold"]

        return submission.rating_sum >= submission.theme.results.accepted_threshold

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

    def to_representation(self, submission):
        """Publish the author's school and club only if the contest shows them."""
        data = super().to_representation(submission)
        if "contest" in self.context:
            contest = self.context["contest"]
        else:
            contest = submission.theme.contest
        if not contest.school_show:
            data["author"]["school"] = None
        if not contest.club_show:
            data["author"]["club"] = None

        return data


class ThemeSubmissionResultsSerializer(SubmissionResultsSerializer):
    """Serialize a submission in published theme results, without its score."""

    class Meta(SubmissionResultsSerializer.Meta):
        """Serializer configuration."""

        fields = [
            field
            for field in SubmissionResultsSerializer.Meta.fields
            if field != "rating"
        ]


class ThemeResultsSerializer(CoreThemeSerializer):
    """Serializer for Theme results."""

    submissions = serializers.SerializerMethodField("get_submissions")

    class Meta(CoreThemeSerializer.Meta):
        """Serializer configuration."""

        fields = CoreThemeSerializer.Meta.fields + [
            "submissions",
        ]

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
