FROM node:12-alpine as base

FROM base as installer
WORKDIR /node
COPY package.json yarn.lock ./
RUN yarn install --no-progress && yarn cache clean
ENV PATH /node/node_modules/.bin:$PATH
WORKDIR /node/app
COPY . .

FROM installer as builder
RUN npm run build

FROM nginx:1.16-alpine
COPY --from=builder /node/app/build /usr/share/nginx/html
COPY docker/default.conf /etc/nginx/conf.d/
