# A BOSH Release for Remote Pairing Sessions

This repository contains a set of BOSH jobs that allows for easy access to
remote pairing sessions.

## SSH Tunnel for remote VNC clients

The SSH tunnel server is as an intermediary between your VNC server and
authorized remote VNC clients. The machine running the VNC server can create a
connection to the tunnel server, and the tunnel server will allow authorized
clients identifying themselves via a token to make connections to this session.
This will enable VNC clients to make a connection that is forwarded to the VNC
server.

### Deployment

#### Prerequisites

- Server key: A private SSH key for identifying the tunnel server
- Authorized keys: All public keys authorized to create a VNC server session.
- Port: A port that the SSH tunnel server is listening on (default: 2222).

  > **NOTE:**
  > Make sure there is a firewall rule in place allowing a connection to
  > this port. Also consider restricting outgoing connections, as the SSH
  > tunnel does not require outgoing connections.

#### Optional

You can specify an `external_ip` to be displayed to the connecting VNC server
session. This should be the same as the static external IP you provide in the
manifest.

Have a look a the [GCE sample manifest](./examples/example-gce-deployment.yml).

### How To Use

To get a working tunnel, two SSH client connections have to be created, one from
the machine acting as VNC server and one from the machine acting as VNC client.
Once the connection is established, it can be closed from either side by
entering the `exit` command in the terminal.

#### VNC Server

```sh
$ ssh -p <SSH_TUNNEL_SERVER_PORT> -i <PATH_TO_PRIVATE_KEY_MATCHING_AUTHORIZED_KEYS> server@<SSH_TUNNEL_SERVER_IP> -R 0:localhost:<VNC_SERVER_PORT>
# example
$ ssh -p 2222 -i /path/to/key server@1.2.3.4 -R 0:localhost:5900
```

This will print a command to create the VNC client connection.

#### VNC Client

You should receive a command from the user setting up the VNC server connection
that includes all the parameters you need to set up to the client connection.

This command will be of the following form:
```sh
$ ssh -p <SSH_TUNNEL_SERVER_PORT> <TOKEN_FROM_VNC_SERVER_CONNECTION>@<SSH_TUNNEL_SERVER_IP> -L <LOCAL_VNC_PORT>:localhost:<REMOTE_PORT_FROM_VNC_SERVER_CONNECTION>
# example
$ ssh -p 2222 tokenblabla@1.2.3.4 -L 6000:localhost:54542
```

Point your VNC client to localhost:6000 (localhost:<LOCAL_VNC_PORT>), and you
should be connected.
```sh
# e.g., on OS X
open vnc://localhost:6000
```
