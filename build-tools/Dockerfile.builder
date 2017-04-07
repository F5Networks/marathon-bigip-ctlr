FROM python:2.7-alpine

COPY entrypoint.builder.sh /entrypoint.sh
COPY marathon-build-requirements.txt /tmp/build-requirements.txt
COPY marathon-runtime-requirements.txt /tmp/runtime-requirements.txt

RUN apk add --no-cache \
		bash \
		gcc \
		musl-dev \
		libffi-dev \
		openssl-dev \
		su-exec && \
	pip install -r /tmp/build-requirements.txt && \
	pip install -r /tmp/runtime-requirements.txt && \
	
ENTRYPOINT [ "/entrypoint.sh" ]
CMD [ "/bin/bash" ]
