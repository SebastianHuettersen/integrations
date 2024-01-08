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

{{event "log"}}

{{fields "log"}}
