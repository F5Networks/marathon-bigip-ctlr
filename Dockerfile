FROM debian:jessie

RUN mkdir /f5-marathon-lb

COPY requirements.txt /f5-marathon-lb/requirements.txt

RUN apt-get update && apt-get install -y python python-dev python-pip openssl libssl-dev \
    build-essential python-dateutil libffi-dev \
    && pip install -r /f5-marathon-lb/requirements.txt \
    && apt-get remove -yf --auto-remove python-dev libssl-dev libffi-dev build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "/f5-marathon-lb/run" ]
WORKDIR /f5-marathon-lb
COPY  . /f5-marathon-lb
