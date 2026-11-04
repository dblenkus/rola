"""Collect the Rolca API routes that the host registers on its router."""

from rolca.core.api import urls as core_api_urls
from rolca.payment.api import urls as payment_api_urls
from rolca.rating.api import urls as rating_api_urls

route_lists = [
    core_api_urls.routeList,
    payment_api_urls.routeList,
    rating_api_urls.routeList,
]
