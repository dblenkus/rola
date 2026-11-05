FROM node:26.13.0-alpine3.24 AS dependencies
WORKDIR /app
RUN chown node:node /app
USER node
COPY --chown=node:node package.json package-lock.json .npmrc ./
RUN npm ci

FROM dependencies AS development
EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]

FROM dependencies AS build
COPY --chown=node:node . .
ARG VITE_PAYPAL_CLIENT_ID
RUN test -n "$VITE_PAYPAL_CLIENT_ID" \
    || { echo "Set the VITE_PAYPAL_CLIENT_ID build argument." >&2; exit 1; }
RUN npm run build

FROM nginx/nginx-unprivileged:1.30.6-alpine3.24 AS production
COPY docker/default.conf /etc/nginx/conf.d/default.conf
RUN nginx -t
COPY --from=build /app/dist /usr/share/nginx/html
