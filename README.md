# f5-marathon-lb
f5-marathon-lb is a tool for managing F5 BIG-IP, by consuming [Marathon's](https://github.com/mesosphere/marathon) app state.

## Architecture
The f5-marathon-lb is a service discovery and load balancing tool for Marathon to configure an F5 BIG-IP. It reads the Marathon task information and dynamically generates BIG-IP configuration details.  

f5-marathon-lb listens to the Marathon event stream and automatically updates the configuration of the BIG-IP and does the following: 

 - Matches Marathon apps by the specified BIG-IP partition
 - Creates a Virtual Server and pool for each app type in Marathon that matches the BIG-IP partition
 - For each task, creates a pool member and adds the member to the server pool 
 - If the app has a Marathon Health Monitor configured, creates a corresponding health monitor for each BIG-IP pool member 

To gather the task information, f5-marathon-lb needs to know where to find Marathon. The service configuration details are stored in labels.  

## Configuration

First, f5-marathon-lb needs to know how to connect to Marathon and the BIG-IP, which is done via the command-line arguments:


```console
usage: f5_marathon_lb.py [-h] [--longhelp]
                         [--marathon MARATHON [MARATHON ...]]
                         [--listening LISTENING] [--callback-url CALLBACK_URL]
                         [--hostname HOSTNAME] [--username USERNAME]
                         [--password PASSWORD] [--partition PARTITION]
                         [--command COMMAND] [--sse] [--health-check]
                         [--dont-bind-http-https] [--ssl-certs SSL_CERTS]
                         [--syslog-socket SYSLOG_SOCKET]
                         [--log-format LOG_FORMAT]
                         [--marathon-auth-credential-file MARATHON_AUTH_CREDENTIAL_FILE]
```

_The **marathon**, **hostname**, **username**, **password**, and **partition** arguments are mandatory_

### Application Labels

Applications to be managed by f5-marathon-lb are identified and configured via their _Marathon Labels_. Some labels are specified _per service port_. These are denoted with the `{n}` parameter in the label key, where `{n}` corresponds to the service port index, beginning at `0`.

The full list of labels which can be specified are:

```
 F5_PARTITION

    The BIG-IP partition to be configured

 F5_{n}_STICKY

    Enable sticky request routing for the service
    Ex: F5_0_STICKY = true

 F5_{n}_REDIRECT_TO_HTTPS

    Redirect HTTP traffic to HTTPS
    Ex: F5_0_REDIRECT_TO_HTTPS = true

 F5_{n}_SSL_CERT

    Enable the given SSL certificate for TLS/SSL traffic
    Ex: F5_0_SSL_CERT = '/etc/ssl/certs/marathon.mesosphere.com'

 F5_{n}_BIND_OPTIONS

    Set additional bind options
    Ex: F5_0_BIND_OPTIONS = 'ciphers AES128+EECDH:AES128+EDH force-tlsv12 no-sslv3'

 F5_{n}_BIND_ADDR

    Bind to the specific address for the service
    Ex: F5_0_BIND_ADDR = '10.0.0.42'

 F5_{n}_POR

    Bind to the specific port for the service
    This overrides the servicePort which has to be unique
    Ex: F5 _ 0 _ PORT = 80

 F5_{n}_MODE

    Set the connection mode to either TCP or HTTP. The default is TCP.
    Ex: F5_0_MODE = 'http'

 F5_{n}_BALANCE

    Set the load balancing algorithm to be used in a backend. The default is roundrobin.
    Ex: F5_0_BALANCE = 'leastconn'
```

### Building and Running

The following shows how to build and launch f5-marathon-lb as a Docker container. 

Build a Docker container:

```console
    docker build -t docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest .
```

Push it to a Docker registry:

```console
    docker push docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest
```

Launch it in Marathon:

```console
    curl -X POST -H "Content-Type: application/json" http://10.141.141.10:8080/v2/apps -d @f5-marathon-lb.json
```

Where "f5-marathon-lb.json" contains the details needed to deploy the container in Marathon, e.g.:

```json
{
  "id": "f5-marathon-lb",
  "cpus": 0.5,
  "mem": 128.0,
  "instances": 1,
  "container": {
    "type": "DOCKER",
    "forcePullImage": true,
    "docker": {
      "image": "docker-registry.pdbld.f5net.com/darzins/f5-marathon-lb:latest",
      "network": "BRIDGE"
    }
  },
  "args": [
    "sse",
    "--marathon", "http://10.141.141.10:8080",
    "--partition", "mesos_1",
    "--hostname", "10.128.1.145",
    "--username", "admin",
    "--password", "default"
  ]
}
```

The following is an example for an application deployment in Marathon, with the appropriate f5-marathon-lb labels configured:    

```json
{
  "id": "server-app",
  "cpus": 0.1,
  "mem": 16.0,
  "container": {
    "type": "DOCKER",
    "docker": {
      "image": "edarzins/node-web-app",
      "network": "BRIDGE",
      "forcePullImage": true,
      "portMappings": [
        { "containerPort": 8088,
          "hostPort": 0,
          "protocol": "tcp" }
      ]
    }
  },
  "labels": {
    "F5_PARTITION": "mesos_1",
    "F5_0_BIND_ADDR": "10.128.10.240",
    "F5_0_PORT": "80",
    "F5_0_MODE": "http"
  },
  "healthChecks": [
    {
      "protocol": "HTTP",
      "portIndex": 0,
      "path": "/",
      "gracePeriodSeconds": 5,
      "intervalSeconds": 20,
      "maxConsecutiveFailures": 3
    }
  ]
}
```
