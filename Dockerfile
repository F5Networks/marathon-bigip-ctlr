FROM golang:alpine

ENV APPPATH /app

RUN mkdir -p "$APPPATH" && chmod -R 777 "$APPPATH"
WORKDIR $APPPATH

COPY requirements.txt $APPPATH

# Install dependencies, build, and remove the dependencies.
RUN apk add --update git gcc musl-dev python python-dev py-pip openssl openssl-dev libffi-dev && \
    pip install -r $APPPATH/requirements.txt && \
    apk del gcc git musl-dev python-dev openssl-dev libffi-dev && \
    rm -rf /var/cache/apk/*

# Move the marathon-bigip-ctlr files into place
COPY run $APPPATH
COPY marathon-bigip-ctlr.py $APPPATH
COPY common.py $APPPATH
COPY _f5.py $APPPATH

# The run script is the entry point to marathon-bigip-ctlr
ENTRYPOINT [ "/app/run" ]
