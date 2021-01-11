FROM python:3.8-slim-buster

COPY . /app
RUN apt-get update ; apt-get install -y graphviz
RUN mkdir -p /storage
RUN pip install /app
ENV XDG_DATA_HOME /storage

CMD sh
