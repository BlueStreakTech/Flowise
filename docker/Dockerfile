FROM node:14.20.0-alpine

USER root

RUN apk add --no-cache git

# You can install a specific version like: flowise@1.0.0
RUN npm install -g flowise

WORKDIR /data

CMD "flowise"