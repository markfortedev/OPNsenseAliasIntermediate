# OPNsense Alias API

Intermediate API to add an IP to an OPNsense Alias

## Running
Example usage with Docker Compose

    version: "3.8"
    services:
      opnapi:
        image: 'ghcr.io/markfortedev/opnsensealiasintermediate:master'
        restart: unless-stopped
        ports:
        - '12356:12356'
        environment:
          OPNSENSE_ADDR: "10.0.0.1"
          APIKEY: "key"
          APIPASS: "secret"
          ALIAS_NAME: "alias"

### Environment Variables

| Variable      | Description      |
|---------------|------------------|
| OPNSENSE_ADDR | OPNsense Address |
| APIKEY        |Key for OPNsense API|
| APIPASS | Secret for OPNsense API|
|ALIAS_NAME|Name of OPNsense Alias to add IPs to|
|IGNORE_CERT|Ignore https self signed certificate errors. Default true|
