FROM golang:1.19.4-bullseye

RUN apt-get update && \
    apt-get -y install libsofthsm2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
