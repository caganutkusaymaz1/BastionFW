# BastionFW Installation and User Guide

This guide explains how to install and run BastionFW with Docker on a Linux
server.

## 1. Prerequisites

Install the following tools before starting:

- Docker
- Docker Compose

## 2. Quick Start

Extract the BastionFW package and enter its directory:

```bash
cd bastionfw
```

Configure the protected site in `docker-compose.yml` by setting `TARGET_URL`:

```yaml
environment:
  - TARGET_URL=https://your-website.example
```

Build and start the container with one command:

```bash
docker compose up --build -d
```

## 3. Dashboard

After startup, open the dashboard at:

```text
http://<server-ip-address>:8080
```

The dashboard displays detected threats, security alerts, live log activity,
processed data, firewall protection, and system health metrics.

## 4. Administration

Check running containers:

```bash
docker ps
```

Inspect recent logs:

```bash
docker logs --tail 50 -f bastionfw-engine
```

Stop the system:

```bash
docker compose down
```

## 5. Troubleshooting

If the dashboard is unreachable, verify that port 8080 accepts inbound traffic
in the server firewall and cloud-provider network policy. The address
`http://127.0.0.1:8080` is reachable only from the server itself; remote users
must use the server's actual IP address.

If the container fails to start, inspect the service output with:

```bash
docker logs bastionfw-engine
```
