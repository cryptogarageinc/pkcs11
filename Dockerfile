FROM golang:1.19.4-buster

RUN apt-get update && apt-get -y install libsofthsm2

WORKDIR /workspace
