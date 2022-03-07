FROM golang:1.17.8-alpine3.15

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh

WORKDIR /usr/src
COPY . .
