FROM python:3.9

LABEL maintainer="radhouene.azzabi@cea.fr"

ARG DEBIAN_FRONTEND="noninteractive"
ENV TZ=Europe/PAris

#-----------------------------------
#Install PM2 
#-----------------------------------
RUN mkdir -p /etc/apt/keyrings && \ 
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg
RUN echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list
RUN apt-get update && apt-get install nodejs -y
RUN npm install -g pm2

#-----------------------------------
#Install Credentials Manager app 
#-----------------------------------
WORKDIR /app
COPY ./app /app

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt

EXPOSE 8080
# CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]