FROM ubuntu:xenial

ENV APPPATH /wkdir
WORKDIR /wkdir

COPY requirements.txt $APPPATH
COPY requirements.docs.txt $APPPATH

RUN set -x && \
  apt-get update && \
  apt-get install -y \
    git \
    python-dev \
    python-pip && \
  pip install -r requirements.txt && \
  pip install flake8 flake8_docstrings mock && \
  pip install -r requirements.docs.txt

CMD [ "/bin/bash" ]
