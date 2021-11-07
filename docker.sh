#!/bin/bash

mkdir docker
mkdir docker/templates
mkdir docker/static

cp app.py docker/.
cp requirements.txt docker/.
cp -r templates/* docker/templates/.
cp -r static/* docker/static/.

echo "FROM python" >> docker/Dockerfile

echo "COPY ./static /home/app/static/" >> docker/Dockerfile
echo "COPY ./templates /home/app/templates/" >> docker/Dockerfile
echo "COPY app.py /home/app/" >> docker/Dockerfile
echo "COPY requirements.txt /home/app/" >> docker/Dockerfile

echo "RUN pip install -r /home/app/requirements.txt" >> docker/Dockerfile

echo "EXPOSE 5000" >> docker/Dockerfile

echo "CMD python3 /home/app/app.py" >> docker/Dockerfile

cd docker
docker build -t app .

docker run -t -d -p 8080:8080 --name midtermwebapprunning app

docker ps -a