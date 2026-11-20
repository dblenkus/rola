"""Serve the payment API endpoint."""

from django.shortcuts import get_object_or_404
from drf_spectacular.utils import OpenApiParameter, OpenApiResponse, extend_schema
from rest_framework import mixins, status, viewsets
from rest_framework.response import Response

from rola.common.permissions import IsSuperUser
from rola.entries.models import SubmissionSet
from rola.payments import services
from rola.payments.api.filters import PaymentFilter
from rola.payments.api.serializers import PaymentSerializer
from rola.payments.models import Payment


class PaymentViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """List payments and set a submission set's payment, for superusers."""

    queryset = Payment.objects.order_by("pk")
    serializer_class = PaymentSerializer
    permission_classes = (IsSuperUser,)
    filterset_class = PaymentFilter
    # A submission set has at most one payment, so its id names the payment.
    lookup_field = "submission_set"
    # At most 18 digits, so the id fits a signed 64-bit integer in the query.
    lookup_value_regex = "[0-9]{1,18}"

    @extend_schema(
        parameters=[
            OpenApiParameter(
                "submission_set",
                int,
                OpenApiParameter.PATH,
                description="The id of the submission set that the payment is for.",
            )
        ],
        responses={
            200: OpenApiResponse(
                PaymentSerializer, description="The set's payment, updated."
            ),
            201: OpenApiResponse(
                PaymentSerializer, description="The set's payment, created."
            ),
        },
    )
    def update(self, request, *args, **kwargs):
        """Set whether a submission set is paid, creating its payment if needed.

        Answers 201 when the payment is created and 200 when it existed.
        """
        submission_set = get_object_or_404(
            SubmissionSet, pk=self.kwargs[self.lookup_field]
        )
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        payment, created = services.set_payment(
            submission_set, serializer.validated_data["paid"], request.user
        )
        return Response(
            self.get_serializer(payment).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )
