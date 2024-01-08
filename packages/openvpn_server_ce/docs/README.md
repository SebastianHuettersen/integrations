# OpenVPN Community Edition Server

The OpenVPN Server integration allows you to monitor [OpenVPN Community Edition](https://openvpn.net/blog/openvpn-community-edition-vs-access-server)(CE) Server. [OpenVPN](https://openvpn.net) Server is an open-source software application that allows for the creation of secure and encrypted virtual private networks (VPNs).

Use the OpenVPN Server integration to collect and parse logs related to VPN. Then visualize that data in Kibana, create alerts to notify you if something goes wrong, and reference logs when troubleshooting an issue.

## Data streams

The OpenVPN CE Server integration collects the following types of data: logs

**Logs**  help you keep a record of events that happen on your openvpn server.

## Requirements

You need Elasticsearch for storing and searching your data and Kibana for visualizing and managing it.
You can use our hosted Elasticsearch Service on Elastic Cloud, which is recommended, or self-manage the Elastic Stack on your own hardware.

This integration has been tested against **OpenVPN 2.5.1**

## Setup
For maximum functionality the openvpn logs must be written to a file this can be achieved using the following parameter in the configuration

    log-append  /var/log/openvpn/openvpn.log

## Logs

### OpenVPN Server

The `log` dataset collects the OpenVPN Server logs.

An example event for `log` looks as following:

```json
{
    "@timestamp": "2023-10-14T16:49:29.000Z",
    "agent": {
        "ephemeral_id": "b47abda8-874e-4a1c-8c5e-44c547ec28f8",
        "id": "db2936d8-c4aa-4fc5-a08c-02c2c958f2c3",
        "name": "docker-fleet-agent",
        "type": "filebeat",
        "version": "8.10.1"
    },
    "data_stream": {
        "dataset": "openvpn_server_ce.log",
        "namespace": "ep",
        "type": "logs"
    },
    "ecs": {
        "version": "8.10.0"
    },
    "elastic_agent": {
        "id": "db2936d8-c4aa-4fc5-a08c-02c2c958f2c3",
        "snapshot": false,
        "version": "8.10.1"
    },
    "event": {
        "agent_id_status": "verified",
        "dataset": "openvpn_server_ce.log",
        "ingested": "2023-10-15T18:29:47Z",
        "timezone": "+00:00"
    },
    "host": {
        "architecture": "x86_64",
        "containerized": false,
        "hostname": "docker-fleet-agent",
        "id": "28da52b32df94b50aff67dfb8f1be3d6",
        "ip": [
            "172.22.0.7"
        ],
        "mac": [
            "02-42-AC-16-00-07"
        ],
        "name": "docker-fleet-agent",
        "os": {
            "codename": "focal",
            "family": "debian",
            "kernel": "6.5.0-1-amd64",
            "name": "Ubuntu",
            "platform": "ubuntu",
            "type": "linux",
            "version": "20.04.6 LTS (Focal Fossa)"
        }
    },
    "input": {
        "type": "log"
    },
    "log": {
        "file": {
            "path": "/tmp/service_logs/openvpn_server.log"
        },
        "offset": 0
    },
    "message": "OpenVPN 2.5.1 x86_64-pc-linux-gnu [SSL (OpenSSL)] [LZO] [LZ4] [EPOLL] [PKCS11] [MH/PKTINFO] [AEAD] built on May 14 2021"
}
```

**Exported fields**

| Field | Description | Type |
|---|---|---|
| @timestamp | Event timestamp. | date |
| cloud.account.id | The cloud account or organization id used to identify different entities in a multi-tenant environment. Examples: AWS account id, Google Cloud ORG Id, or other unique identifier. | keyword |
| cloud.availability_zone | Availability zone in which this host is running. | keyword |
| cloud.image.id | Image ID for the cloud instance. | keyword |
| cloud.instance.id | Instance ID of the host machine. | keyword |
| cloud.instance.name | Instance name of the host machine. | keyword |
| cloud.machine.type | Machine type of the host machine. | keyword |
| cloud.project.id | Name of the project in Google Cloud. | keyword |
| cloud.provider | Name of the cloud provider. Example values are aws, azure, gcp, or digitalocean. | keyword |
| cloud.region | Region in which this host is running. | keyword |
| container.image.name | Name of the image the container was built on. | keyword |
| container.labels | Image labels. | object |
| container.name | Container name. | keyword |
| data_stream.dataset | Data stream dataset. | constant_keyword |
| data_stream.namespace | Data stream namespace. | constant_keyword |
| data_stream.type | Data stream type. | constant_keyword |
| ecs.version | ECS version this event conforms to. `ecs.version` is a required field and must exist in all events. When querying across multiple indices -- which may conform to slightly different ECS versions -- this field lets integrations adjust to the schema version of the events. | keyword |
| event.module | Name of the module this data is coming from. | constant_keyword |
| host.architecture | Operating system architecture. | keyword |
| host.containerized | If the host is a container. | boolean |
| host.domain | Name of the domain of which the host is a member. For example, on Windows this could be the host's Active Directory domain or NetBIOS domain name. For Linux this could be the domain of the host's LDAP provider. | keyword |
| host.hostname | Hostname of the host. It normally contains what the `hostname` command returns on the host machine. | keyword |
| host.id | Unique host id. As hostname is not always unique, use values that are meaningful in your environment. Example: The current usage of `beat.name`. | keyword |
| host.ip | Host ip addresses. | ip |
| host.mac | Host mac addresses. | keyword |
| host.name | Name of the host. It can contain what `hostname` returns on Unix systems, the fully qualified domain name, or a name specified by the user. The sender decides which value to use. | keyword |
| host.os.build | OS build information. | keyword |
| host.os.codename | OS codename, if any. | keyword |
| host.os.family | OS family (such as redhat, debian, freebsd, windows). | keyword |
| host.os.kernel | Operating system kernel version as a raw string. | keyword |
| host.os.name | Operating system name, without the version. | keyword |
| host.os.name.text | Multi-field of `host.os.name`. | text |
| host.os.platform | Operating system platform (such centos, ubuntu, windows). | keyword |
| host.os.version | Operating system version as a raw string. | keyword |
| host.type | Type of host. For Cloud providers this can be the machine type like `t2.medium`. If vm, this could be the container, for example, or other information meaningful in your environment. | keyword |
| input.type | Input type | keyword |
| interface.name | Interface name as reported by the system. | keyword |
| log.file.path | Full path to the log file this event came from. |  |
| log.offset | Log offset | long |
| log.source.address | Source address from which the log event was read / sent from. | keyword |
| message |  | match_only_text |
| network.protocol | In the OSI Model this would be the Application Layer protocol. For example, `http`, `dns`, or `ssh`. The field value must be normalized to lowercase for querying. | keyword |
| openvpn.cipher | Used Cipher for the connection. | keyword |
| openvpn.client.ciphers | Client announced supported ciphers. | keyword |
| openvpn.client.control.config | Options pushed to the Client from the server. | keyword |
| openvpn.client.control.status | Status of the pushed config to the Client. | keyword |
| openvpn.client.gui.version | The client used UI version. | keyword |
| openvpn.client.id | A unique and persistent ID of the client. | keyword |
| openvpn.client.lz4 | If the client supports LZ4 compressions. | keyword |
| openvpn.client.lzo | If client was built with LZO stub capability. | keyword |
| openvpn.client.mtu | The client announced support of pushable MTU and the maximum MTU it is willing to accept. | keyword |
| openvpn.client.os.platform | The client operating system platform. | keyword |
| openvpn.client.os.version | The client running operating system version. | keyword |
| openvpn.client.peer_info | Information of the openvpn client. | keyword |
| openvpn.client.protocol_extensions | Details about protocol extensions that the peer supports. | keyword |
| openvpn.client.session.id | Client session id. | keyword |
| openvpn.client.tcp_nonlinear_mode | client indicates its ability to process non-linear packet ID sequences in TCP mode. | keyword |
| openvpn.client.version | The client used OpenVPN version. | keyword |
| openvpn.event.type.name | OpenVPN event type. | keyword |
| openvpn.exit.code | Reaseon of the session close | keyword |
| openvpn.hash | Used message hash for the connection. | keyword |
| openvpn.server.cipher | Used Cipher for the connection. | keyword |
| openvpn.server.gateway | Used Gateway of the openvpn Server. | ip |
| openvpn.server.hash | Used Hash for the connection. | keyword |
| openvpn.server.mtu | The MTU set on the openvpn server Interface. | keyword |
| process.name | Process name. Sometimes called program name or similar. | keyword |
| process.name.text | Multi-field of `process.name`. | match_only_text |
| source.address | Some event source addresses are defined ambiguously. The event will sometimes list an IP, a domain or a unix socket.  You should always store the raw address in the `.address` field. Then it should be duplicated to `.ip` or `.domain`, depending on which one it is. | keyword |
| source.as.number | Unique number allocated to the autonomous system. The autonomous system number (ASN) uniquely identifies each network on the Internet. | long |
| source.as.organization.name | Organization name. | keyword |
| source.as.organization.name.text | Multi-field of `source.as.organization.name`. | match_only_text |
| source.bytes | Bytes sent from the source to the destination. | long |
| source.domain | The domain name of the source system. This value may be a host name, a fully qualified domain name, or another host naming format. The value may derive from the original event or be added from enrichment. | keyword |
| source.geo.city_name | City name. | keyword |
| source.geo.continent_name | Name of the continent. | keyword |
| source.geo.country_iso_code | Country ISO code. | keyword |
| source.geo.country_name | Country name. | keyword |
| source.geo.location | Longitude and latitude. | geo_point |
| source.geo.name | User-defined description of a location, at the level of granularity they care about. Could be the name of their data centers, the floor number, if this describes a local physical entity, city names. Not typically used in automated geolocation. | keyword |
| source.geo.region_iso_code | Region ISO code. | keyword |
| source.geo.region_name | Region name. | keyword |
| source.ip | IP address of the source (IPv4 or IPv6). | ip |
| source.mac | MAC address of the source. The notation format from RFC 7042 is suggested: Each octet (that is, 8-bit byte) is represented by two [uppercase] hexadecimal digits giving the value of the octet as an unsigned integer. Successive octets are separated by a hyphen. | keyword |
| source.nat.ip | Translated ip of source based NAT sessions (e.g. internal client to internet) Typically connections traversing load balancers, firewalls, or routers. | ip |
| source.port | Port of the source. | long |
| tags | List of keywords used to tag each event. | keyword |
| tls.cipher | String indicating the cipher used during the current connection. | keyword |
| tls.curve | String indicating the curve used for the given cipher, when applicable. | keyword |
| tls.version | Numeric part of the version parsed from the original string. | keyword |
| user.name | Short name or login of the user. | keyword |
| user.name.text | Multi-field of `user.name`. | match_only_text |

