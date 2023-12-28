FROM node:18-alpine

USER root

RUN apk add --no-cache git
RUN apk add --no-cache python3 py3-pip make g++
# needed for pdfjs-dist
RUN apk add --no-cache build-base cairo-dev pango-dev

# Install Chromium
RUN apk add --no-cache chromium

# Install Package for Turbo Repo (fix as shown here: https://github.com/vercel/turbo/issues/3373)
RUN apk add --no-cache libc6-compat 

WORKDIR /root/flowise

# Install Yarn
# RUN npm install --global yarn

ENV PUPPETEER_SKIP_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

COPY . /root/flowise

RUN yarn install
# RUN yarn build

# EXPOSE 3000
# EXPOSE 8080

ENTRYPOINT ["tail", "-f", "/dev/null"]