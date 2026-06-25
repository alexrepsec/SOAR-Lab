# SOAR Lab: Wazuh + Shuffle + TheHive + VirusTotal + AbuseIPDB

Implementation of a **SOAR (Security Orchestration, Automation and Response)** flow connecting a SIEM (Wazuh) with an automation platform (Shuffle), an incident management system (TheHive), and two threat intelligence sources (VirusTotal and AbuseIPDB).

The goal: when Wazuh detects a suspicious indicator (file hash or IP address), Shuffle automatically enriches it against VirusTotal and AbuseIPDB, and if it's confirmed as malicious, creates a case in TheHive with no manual intervention.

---

## Table of Contents

1. [Architecture](#architecture)
2. [Prerequisites](#prerequisites)
3. [Installing Shuffle](#installing-shuffle)
4. [Configuring the Integrations (Apps)](#configuring-the-integrations-apps)
   - [TheHive](#thehive-integration)
   - [VirusTotal](#virustotal-integration)
   - [AbuseIPDB](#abuseipdb-integration)
   - [Wazuh](#wazuh-integration)
5. [Workflow 1: Malicious Hash Detection](#workflow-1-malicious-hash-detection)
6. [Workflow 2: Malicious IP Detection](#workflow-2-malicious-ip-detection)
7. [Testing](#testing)
8. [Screenshots](#screenshots)

---

## Architecture

```
┌─────────┐      Webhook       ┌──────────┐
│  Wazuh  │ ──────────────────▶│ Shuffle  │
└─────────┘   (hash / IP)      └────┬─────┘
                                     │
                  ┌──────────────────┼──────────────────┐
                  ▼                                      ▼
           ┌─────────────┐                      ┌──────────────┐
           │ VirusTotal  │                       │  AbuseIPDB   │
           │   (hash)    │                       │     (IP)     │
           └──────┬──────┘                       └──────┬───────┘
                  │                                      │
                  └──────────────────┬───────────────────┘
                                      ▼
                              Is it malicious?
                                      │
                            ┌─────────┴─────────┐
                            ▼                   ▼
                       Yes: create case     No: end flow
                       in TheHive
```

**Components:**

| Component | Role | Default Port |
|---|---|---|
| Wazuh | SIEM, generates the initial alerts | 1514 / 55000 |
| Shuffle | Orchestration and automation engine (SOAR) | 3001 |
| TheHive | Case and incident management | 9000 |
| VirusTotal | Threat intel for file hashes | Public API |
| AbuseIPDB | Threat intel for IP reputation | Public API |

---

## Prerequisites

- Ubuntu Server 22.04 LTS
- Docker and Docker Compose v2 installed
- Minimum 4 GB RAM available for Shuffle (8 GB+ recommended if running alongside TheHive)
- `vm.max_map_count` set to at least `262144` (required by OpenSearch)
- Wazuh and TheHive already installed and running
- Accounts and API keys for:
  - [VirusTotal](https://www.virustotal.com/) (free or paid tier)
  - [AbuseIPDB](https://www.abuseipdb.com/) (free or paid tier)

---

## Installing Shuffle

### 1. Clone the official repository

```bash
git clone https://github.com/Shuffle/Shuffle.git
cd Shuffle
```

### 2. Prepare the host environment

```bash
# Correct permissions for the database folder
sudo chown -R 1000:1000 shuffle-database

# Disable swap (required by OpenSearch)
sudo swapoff -a

# Increase the virtual memory map count limit
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 3. Start the services

```bash
sudo docker compose up -d
```

This creates and starts the main containers:

- `shuffle-frontend` (ports 3001/3443)
- `shuffle-backend` (port 5001)
- `shuffle-opensearch` (ports 9200/9600/9300)
- `shuffle-orborus` (worker orchestrator)

### 4. Verify the status

```bash
sudo docker compose ps
```

All services should show `Up` status. The first run may take 1-2 minutes to become fully available while OpenSearch finishes initializing.

### 5. Access the web interface

Open in your browser:

```
http://<server-ip>:3001
```

On first access, you'll be prompted to create the admin user (`/loginsetup`).

---

## Configuring the Integrations (Apps)

Inside Shuffle, integrations are managed as **Apps** within each workflow. Each app requires its own authentication.

### TheHive Integration

1. In the workflow, add the **TheHive** app from the side Apps panel.
2. Configure authentication:
   - **URL**: `https://<thehive-ip>:9000`
   - **API Key**: generated in TheHive under `My profile → API Key`
3. Main actions used in this project:
   - `Create Alert` — creates an alert with the analyzed indicator's data
   - `Create Case` — creates a case directly (alternative to the alert)

### VirusTotal Integration

1. Add the **VirusTotal v3** app.
2. Configure authentication with your **API Key** (obtained from your VirusTotal profile).
3. Action used: `Get a file report` — takes the hash (MD5/SHA1/SHA256) and returns the antivirus engines' detection report.
4. Key response field: `data.attributes.last_analysis_stats.malicious` (number of engines that flagged the file as malicious).

### AbuseIPDB Integration

1. Add the **AbuseIPDB** app.
2. Configure authentication with your **API Key**.
3. Action used: `Check an IP address` — takes the IP and returns its reputation score.
4. Key response field: `data.abuseConfidenceScore` (0-100; higher values indicate a higher likelihood of malicious activity).

### Wazuh Integration

Wazuh isn't connected as an App inside Shuffle; instead, **Shuffle exposes a Webhook** that Wazuh calls when a rule is triggered.

1. In the Shuffle workflow, add a **Webhook** trigger.
2. Copy the generated URL, in the format:
   ```
   http://<shuffle-ip>:3001/api/v1/hooks/webhook_<id>
   ```
3. In Wazuh, configure an **Integration script** or an `active-response` rule that sends a `POST` request to that URL when the alert condition is met (for example, a hash detected via FIM or an IP found in the logs).

Example custom integration configuration in Wazuh's `ossec.conf`:

```xml
<integration>
  <name>custom-shuffle</name>
  <hook_url>http://<shuffle-ip>:3001/api/v1/hooks/webhook_<id></hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

---

## Workflow 1: Malicious Hash Detection

**Workflow name:** `Malware Hash Detection`

**Logic:**

1. **Trigger – Webhook** (`Wazuh_Alert_Receiver`): receives the JSON alert from Wazuh, including the suspicious file's hash.
2. **VirusTotal v3 – Get a file report**: queries the received hash.
3. **Condition (If/Change Me)**: evaluates whether `last_analysis_stats.malicious > 0`.
4. **If malicious → TheHive – Create Alert**: creates an alert with:
   - Title: `Malware detected - Wazuh`
   - Analyzed hash
   - Number of engines that flagged it
   - Severity adjusted based on the score
5. **If clean → end of flow** (no case is created, avoiding noise in TheHive).

### Main variables used

| Variable | Source | Use |
|---|---|---|
| `$hash` | Wazuh webhook payload | Input for VirusTotal |
| `$malicious_count` | VirusTotal response | Input for the condition |
| `$source_ip` / `$agent_name` | Wazuh webhook payload | Context included in the TheHive case |

---

## Workflow 2: Malicious IP Detection

**Workflow name:** `Malicious IP Detection`

**Logic:**

1. **Trigger – Webhook**: receives the JSON alert from Wazuh, including the suspicious source IP.
2. **AbuseIPDB – Check an IP address**: queries the received IP.
3. **Condition (If/Change Me)**: evaluates whether `abuseConfidenceScore >= 50` (configurable threshold).
4. **If threshold exceeded → TheHive – Create Alert**: creates an alert with:
   - Title: `Malicious IP detected - Wazuh`
   - Analyzed IP
   - Abuse confidence score
   - Country of origin and report categories (from the AbuseIPDB response)
5. **If below threshold → end of flow**.

### Main variables used

| Variable | Source | Use |
|---|---|---|
| `$ip` | Wazuh webhook payload | Input for AbuseIPDB |
| `$abuse_score` | AbuseIPDB response | Input for the condition |
| `$country_code` | AbuseIPDB response | Context included in the TheHive case |

---

## Testing

To test each workflow without waiting for a real Wazuh alert, Shuffle lets you trigger the webhook manually:

```bash
# Test the hash workflow
curl -X POST http://<shuffle-ip>:3001/api/v1/hooks/webhook_<id> \
  -H "Content-Type: application/json" \
  -d '{"hash": "44d88612fea8a8f36de82e1278abb02f", "agent_name": "test-agent"}'

# Test the IP workflow
curl -X POST http://<shuffle-ip>:3001/api/v1/hooks/webhook_<id> \
  -H "Content-Type: application/json" \
  -d '{"ip": "118.25.6.39", "agent_name": "test-agent"}'
```

> The hash `44d88612fea8a8f36de82e1278abb02f` corresponds to a well-known test file (EICAR), useful for validating detection without using real malware.

---

## Screenshots

> _Pending: add screenshots of the workflow built in the Shuffle editor, the alert created in TheHive, and the result of the `curl` test._

---

## ⚠️ Disclaimer
 
This project is for **educational purposes only**. All testing was performed on isolated virtual machines owned and controlled by the author. Never run network attacks against systems you do not own or have explicit permission to test.
 
---
 
## 👤 Author

**alexrepsec**  
Cybersecurity enthusiast | Home Lab Builder
 
*This project was built as part of a cybersecurity portfolio to demonstrate practical SOC automation, AI-powered threat detection, and network traffic analysis skills.*
