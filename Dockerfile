FROM debian:jessie

ENTRYPOINT [ "/f5-marathon-lb/run" ]
CMD        [ "sse", "-m", "http://10.190.20.27:8080", "--group", "*", "--haproxy-config", "f5_config.json" ]
EXPOSE     80 81 443 9090

COPY  . /f5-marathon-lb

#RUN apt-get update && apt-get install -y python3 python3-pip openssl libssl-dev runit \
#    wget build-essential libpcre3 libpcre3-dev python3-dateutil socat iptables libreadline-dev \
#    && pip3 install -r /marathon-lb/requirements.txt \
#    && /marathon-lb/build-haproxy.sh \
#    && apt-get remove -yf --auto-remove wget libssl-dev build-essential libpcre3-dev libreadline-dev \
#    && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y python python-dev python-pip openssl libssl-dev \
    wget build-essential python-dateutil libffi-dev \
    && pip install -r /f5-marathon-lb/requirements.txt \
    && apt-get remove -yf --auto-remove wget libssl-dev build-essential libpcre3-dev libreadline-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /f5-marathon-lb
