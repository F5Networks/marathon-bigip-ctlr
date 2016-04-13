FROM debian:jessie

ENTRYPOINT [ "/f5-marathon-lb/run" ]

COPY  . /f5-marathon-lb

RUN apt-get update && apt-get install -y python python-dev python-pip openssl libssl-dev \
    build-essential python-dateutil libffi-dev \
    && pip install -r /f5-marathon-lb/requirements.txt \
    && apt-get remove -yf --auto-remove python-dev libssl-dev libffi-dev build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /f5-marathon-lb
