FROM python:3.12-alpine

ARG EDC_CONNECTOR_SCHEME=http
ENV EDC_CONNECTOR_SCHEME=${EDC_CONNECTOR_SCHEME}

ARG EDC_CONNECTOR_HOST
ENV EDC_CONNECTOR_HOST=${EDC_CONNECTOR_HOST}

ARG EDC_CONNECTOR_CONNECTOR_ID
ENV EDC_CONNECTOR_CONNECTOR_ID=${EDC_CONNECTOR_CONNECTOR_ID}

ARG EDC_CONNECTOR_PARTICIPANT_ID
ENV EDC_CONNECTOR_PARTICIPANT_ID=${EDC_CONNECTOR_PARTICIPANT_ID}

ARG EDC_CONNECTOR_MANAGEMENT_PORT=80
ENV EDC_CONNECTOR_MANAGEMENT_PORT=${EDC_CONNECTOR_MANAGEMENT_PORT}

ARG EDC_CONNECTOR_CONTROL_PORT=80
ENV EDC_CONNECTOR_CONTROL_PORT=${EDC_CONNECTOR_CONTROL_PORT}

ARG EDC_CONNECTOR_PUBLIC_PORT=80
ENV EDC_CONNECTOR_PUBLIC_PORT=${EDC_CONNECTOR_PUBLIC_PORT}

ARG EDC_CONNECTOR_PROTOCOL_PORT=80
ENV EDC_CONNECTOR_PROTOCOL_PORT=${EDC_CONNECTOR_PROTOCOL_PORT}

ARG EDC_CONNECTOR_API_KEY
ENV EDC_CONNECTOR_API_KEY=${EDC_CONNECTOR_API_KEY}

ARG EDC_CONNECTOR_API_KEY_HEADER=X-API-Key
ENV EDC_CONNECTOR_API_KEY_HEADER=${EDC_CONNECTOR_API_KEY_HEADER}

WORKDIR /opt/examples
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
