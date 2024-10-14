FROM gradle:7.6.0-jdk17 AS build-env

WORKDIR /opt/src/connector/openapi-connector


COPY ./connector .

ARG CLEAN=true
ARG SSI=false

ENV ORG_GRADLE_PROJECT_useSSI=$SSI


RUN if [ "$CLEAN" = "true" ]; then \
        ./gradlew clean build -PtaskThreads=2 --max-workers=2; \
    else \
        ./gradlew build -PtaskThreads=2 --max-workers=2; \
    fi


FROM openjdk:17-bullseye


RUN apt-get update -y && apt-get install -y avahi-utils


WORKDIR /opt/src/connector/openapi-connector

COPY --from=build-env /opt/src/connector/openapi-connector/build ./build