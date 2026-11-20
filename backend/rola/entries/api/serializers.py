"""Serialize authors, photographs, submissions and submission sets."""

from rest_framework import serializers

from rola.common.ids import ID_RANGE
from rola.common.serializers import BaseSerializer
from rola.entries.models import Author, File, Submission, SubmissionSet


class FileSerializer(BaseSerializer):
    """Serializer for File objects."""

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = File
        fields = BaseSerializer.Meta.fields + ["file", "thumbnail"]
        extra_kwargs = {
            "thumbnail": {"required": False},
        }


class AuthorSerializer(BaseSerializer):
    """Serializer for Author objects."""

    email = serializers.SerializerMethodField("get_email")

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Author
        fields = BaseSerializer.Meta.fields + [
            "first_name",
            "last_name",
            "email",
            "date_of_birth",
            "school",
            "mentor",
            "club",
            "distinction",
        ]

    def get_email(self, author) -> str | None:
        """Return author's email for superusers, ``None`` field otherwise."""
        if not self.context["request"].user.is_superuser:
            return None

        return author.user.email if author.user else author.email


class SubmissionSerializer(BaseSerializer):
    """Represent a submission with its author and photographs."""

    # Typed as fields, as the published results replace both.
    author: serializers.Field = AuthorSerializer()
    files: serializers.Field = FileSerializer(many=True)

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = Submission
        fields = BaseSerializer.Meta.fields + [
            "author",
            "theme",
            "title",
            "description",
            "files",
        ]


class SubmissionSetSerializer(BaseSerializer):
    """Represent a submission set with its submissions and author."""

    submissions = SubmissionSerializer(many=True)
    author = AuthorSerializer()

    class Meta(BaseSerializer.Meta):
        """Serializer configuration."""

        model = SubmissionSet
        fields = BaseSerializer.Meta.fields + ["submissions", "author", "contest"]


def _id_field() -> serializers.IntegerField:
    """Return a field for an id, refusing values the databases cannot store."""
    return serializers.IntegerField(
        min_value=ID_RANGE["min_value"], max_value=ID_RANGE["max_value"]
    )


class SubmissionCreateSerializer(serializers.ModelSerializer[Submission]):
    """One submission of an upload, with its theme and photographs as ids."""

    files = serializers.ListField(child=_id_field(), allow_empty=False)

    class Meta:
        """Serializer configuration."""

        model = Submission
        fields = ["theme", "title", "description", "files"]

    def validate_files(self, value: list[int]) -> list[File]:
        """Resolve the requester's own uploads that no submission holds yet."""
        if len(value) != len(set(value)):
            raise serializers.ValidationError("Each file may only be used once.")
        files = list(
            File.objects.filter(id__in=value, user=self.context["request"].user)
        )
        if len(files) != len(value):
            raise serializers.ValidationError("Files must exist and belong to you.")
        if any(file.submission_id is not None for file in files):
            raise serializers.ValidationError(
                "A file is already attached to another submission."
            )
        by_id = {file.pk: file for file in files}
        return [by_id[pk] for pk in value]


class SubmissionSetCreateSerializer(serializers.Serializer[None]):
    """An upload: the author, as an id, and the submissions entered together."""

    author = _id_field()
    submissions = SubmissionCreateSerializer(many=True, allow_empty=False)

    def validate_author(self, value: int) -> Author:
        """Resolve only authors owned by the requester."""
        try:
            return Author.objects.get(pk=value, user=self.context["request"].user)
        except Author.DoesNotExist as error:
            raise serializers.ValidationError(
                "Author must exist and belong to you."
            ) from error
