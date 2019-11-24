FROM python:3.8-alpine as common
RUN apk add postgresql-dev

FROM common as builder
WORKDIR /install
COPY requirements.txt /requirements.txt
RUN apk add \
    build-base \
    libffi-dev \
    openssl-dev && \
    pip install --prefix=/install --no-warn-script-location \
    -r /requirements.txt \
    daphne==2.4.0

FROM common
COPY --from=builder /install /usr/local
COPY . /app
WORKDIR /app
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "rola.asgi:application"]
