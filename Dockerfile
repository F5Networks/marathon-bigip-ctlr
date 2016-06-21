FROM golang:alpine

ENV APPPATH /app

RUN mkdir -p "$APPPATH" && chmod -R 777 "$APPPATH"
WORKDIR $APPPATH

COPY requirements.txt $APPPATH

# Install dependencies, build, and remove the dependencies.
RUN apk add --update git gcc musl-dev python python-dev py-pip openssl openssl-dev py-dateutil libffi-dev && \
    pip install -r $APPPATH/requirements.txt && \
    apk del git python-dev openssl-dev libffi-dev && \
    rm -rf /var/cache/apk/*

# Move the f5-marathon-lb files into place
COPY run $APPPATH
COPY f5_marathon_lb.py $APPPATH
COPY common.py $APPPATH
COPY _f5.py $APPPATH

# The run script is the entry point to f5-marathon-lb
ENTRYPOINT [ "/app/run" ]
