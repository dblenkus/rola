FROM python:3.8-alpine as common
WORKDIR /app
EXPOSE 8000
RUN addgroup -g 1000 python && \
    adduser -u 1000 -G python -s /bin/sh -D python && \
    apk add --update --no-cache postgresql-dev jpeg-dev

FROM common as builder
WORKDIR /install
COPY requirements.txt requirements.dev.txt /
RUN apk add --update --no-cache \
    build-base \
    rust \
    cargo \
    git \
    libffi-dev \
    openssl-dev \
    zlib-dev && \
    pip install --upgrade pip && \
    CRYPTOGRAPHY_DONT_BUILD_RUST=1 pip install --prefix=/install --no-warn-script-location \
    -r /requirements.txt \
    daphne==2.4.0 \
    ipython \
    jedi==0.17

FROM common
COPY --from=builder /install /usr/local
COPY rola rola
COPY utils utils
COPY drf_user drf_user
COPY manage.py LICENSE ./
RUN python -m compileall rola
USER python
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "rola.asgi:application"]
