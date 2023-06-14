FROM golang:1.20.3-bullseye

RUN apt-get update && \
    apt-get -y install libsofthsm2 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
