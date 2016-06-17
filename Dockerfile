FROM debian:jessie

ENV APPPATH /app

RUN mkdir $APPPATH

COPY requirements.txt $APPPATH/requirements.txt

RUN apt-get update && apt-get install -y python python-dev python-pip openssl libssl-dev \
    build-essential python-dateutil libffi-dev \
    && pip install -r $APPPATH/requirements.txt \
    && apt-get remove -yf --auto-remove python-dev libssl-dev libffi-dev build-essential \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENTRYPOINT [ "$APPPATH/run" ]
WORKDIR $APPPATH
COPY  . $APPPATH
