# 🔍 Splunk SIEM & Log Analysis Lab

**Environment:** Windows Server VM (Lab 1 AD) · Ubuntu 22.04 VM · Splunk Enterprise · Azure VNet  
**Cloud Provider:** Microsoft Azure  
**Certification Alignment:** CompTIA Security+ · CySA+ · Splunk Core Certified User

---

## 📋 What This Lab Is

This lab is where security operations start to feel real. I deployed Splunk Enterprise on an Azure Ubuntu VM, connected it to the Windows Server Active Directory environment from Lab 1 via the Splunk Universal Forwarder, and built a working security monitoring setup from scratch — searches, a live dashboard, and an automated alert.

The skills here map directly to Tier 1–3 SOC work. A SIEM is the primary tool an analyst reaches for when an alert fires or an investigation starts. Knowing how to get data in, write searches that find meaningful signals, and build dashboards that surface threats at a glance is the difference between staring at logs and actually understanding what's happening on a network.

---

## 🏗️ Architecture — How Splunk Receives and Processes Logs

```
┌─────────────────────────────────────────────────────────────────┐
│                    Azure VNet — internal network                 │
│                                                                  │
│  ┌──────────────────────────┐         ┌───────────────────────┐  │
│  │  Windows Server VM       │         │  Splunk VM            │  │
│  │  Lab 1 — Active Dir.     │         │  Ubuntu 22.04 LTS     │  │
│  │                          │         │                       │  │
│  │  ┌────────────────────┐  │         │  ┌─────────────────┐  │  │
│  │  │ Universal Forwarder│──┼─port────┼─▶│    Indexer      │  │  │
│  │  │ inputs.conf        │  │  9997   │  └────────┬────────┘  │  │
│  │  └────────────────────┘  │         │           │           │  │
│  │                          │         │  ┌────────▼────────┐  │  │
│  │  Logs forwarded:         │         │  │ windows_logs    │  │  │
│  │  · Security (4624/4625/  │         │  │ index           │  │  │
│  │    4740)                 │         │  └─────────────────┘  │  │
│  │  · System                │         │                       │  │
│  │  · Application           │         └──────────┬────────────┘  │
│  └──────────────────────────┘                    │               │
│                                              web UI :8000        │
└──────────────────────────────────────────────────┼──────────────┘
                                                   │
                                          ┌────────▼────────┐
                                          │  Analyst browser │
                                          │  Search · Alerts │
                                          │  Dashboards      │
                                          └─────────────────┘
```

The Windows Server VM from Lab 1 runs the Universal Forwarder — a lightweight agent that monitors Windows Event Logs and ships them to Splunk over port 9997 on the internal Azure network. Splunk indexes everything into `windows_logs` and exposes the full web UI on port 8000. Port 9997 is only open to the internal VNet; port 8000 is only open to my IP. Nothing is exposed to the public internet unnecessarily.

**Key Event IDs flowing through this pipeline:**

| Event ID | Meaning |
|---|---|
| `4624` | Successful logon |
| `4625` | Failed logon attempt |
| `4740` | Account lockout |

---

## 🧠 Concepts I Applied

**SIEM (Security Information and Event Management)** is the central platform for security operations. It collects logs from every system in an environment — servers, workstations, firewalls, cloud services — and makes them all searchable in one place. The two core jobs are correlation (connecting events across systems to find patterns no single source would reveal) and alerting (notifying analysts automatically when suspicious conditions are met). Without a SIEM, investigating an incident means logging into dozens of systems individually. With one, you search across everything at once.

**SPL (Splunk Processing Language)** is the query language for asking Splunk questions. It works as a pipeline — start with a search, then pipe results through commands that filter, transform, and visualise. Every search I wrote in this lab follows the same pattern: find the events, then shape the results. It's intuitive once the pipeline model clicks.

**Splunk indexes** are named storage buckets — like database tables — where events live. When logs arrive they're stored in an index; when you search you specify which index to look in. I created a dedicated `windows_logs` index to keep Windows Event Log data separate and easy to reference.

**The Universal Forwarder** is a lightweight agent that runs invisibly on any machine you want to monitor. It reads `inputs.conf` to know what to collect, compresses and encrypts the data, and ships it to the Splunk indexer over port 9997. It uses minimal resources and is how most enterprise environments feed logs into Splunk at scale.

**Windows Event IDs** are numbered codes assigned to every event the Windows operating system records. The three IDs that tell the story of most authentication investigations are 4624 (successful logon), 4625 (failed logon), and 4740 (account lockout). A spike in 4625 events for one account is a brute force attempt. Hundreds of 4625 events spread across many different accounts is a password spray attack. A chain of 4625 events followed by a 4740 confirms the attack hit the lockout threshold.

**`inputs.conf`** is the configuration file that tells the forwarder exactly what data to collect. Each section defines one log source. I configured it to collect Security, System, and Application logs from the Windows VM — the Security log being the most important, since it contains all authentication events.

---

## 🛠️ What I Did

### Step 1 — Deployed Splunk on Azure

Spun up an Ubuntu 22.04 LTS VM in Azure (Standard_B2s — 2 vCPU, 4GB RAM, the minimum Splunk needs to run comfortably). Configured the Network Security Group to allow:
- Port `8000` (Splunk web UI) — my IP only
- Port `9997` (forwarder input) — VNet range only
- Port `22` (SSH) — my IP only

Used a temporary email address to register on splunk.com and downloaded Splunk Enterprise. SSHed into the VM and ran the install:

```bash
# Download Splunk Enterprise
wget -O splunk-10.2.2-linux-amd64.deb "https://download.splunk.com/products/splunk/releases/10.2.2/linux/splunk-10.2.2-80b90d638de6-linux-amd64.deb"

# Install
sudo dpkg -i splunk-10.2.2-linux-amd64.deb

# Start Splunk and set admin credentials
sudo /opt/splunk/bin/splunk start --accept-license

# Enable auto-start on reboot
sudo /opt/splunk/bin/splunk enable boot-start
```

Opened the web UI at `http://<VM_PUBLIC_IP>:8000` and confirmed Splunk was running.

---

### Step 2 — Configured Data Inputs

**In Splunk first:** Navigated to Settings → Forwarding and Receiving → Configure Receiving, added port `9997`, then created a new index named `windows_logs`.

**On the Windows Server VM:** Downloaded and installed the Splunk Universal Forwarder, pointing it at the Splunk VM's private IP on port 9997 during setup. Then created `inputs.conf` at:

```
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf
```

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1

[WinEventLog://System]
disabled = 0

[WinEventLog://Application]
disabled = 0
```

Restarted the forwarder service in PowerShell as Administrator:

```powershell
Restart-Service SplunkForwarder
```

Confirmed data was flowing with a quick search in Splunk:

```
index=windows_logs | head 100
```

Results came back immediately — authentication events from the AD environment were landing in the index.

---

### Step 3 — SPL Searches

All searches run in the Search & Reporting app. The time picker on the right controls the window.

**Find failed login attempts (EventCode 4625):**
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count by Account_Name, Workstation_Name
| sort -count
```
This counts failed logins grouped by username and source machine, sorted highest to lowest. Anything above 5 for a single account in a short window is worth a closer look.

**Find successful logins with logon type (EventCode 4624):**
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| stats count by Account_Name, Logon_Type
| sort -count
```
Logon Type 2 is interactive (keyboard), Type 3 is network (file share), Type 10 is RDP, Type 5 is a service account. Separating by type immediately shows what kind of access is happening.

**Find account lockouts (EventCode 4740):**
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4740
| table _time, Account_Name, Caller_Computer_Name
| sort -_time
```
The `Caller_Computer_Name` field shows where the failed attempts came from — critical for identifying the attacking machine.

**Top 10 failed login usernames — threat hunting:**
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625 earliest=-24h
| stats count as failures by Account_Name
| sort -failures
| head 10
```
Usernames that don't exist in Active Directory appearing here indicate account enumeration — an attacker probing for valid usernames before attempting logins.

**Detect after-hours logins:**
```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 7 OR hour > 19
| table _time, Account_Name, Workstation_Name, Logon_Type
| sort -_time
```
The `eval` command extracts the hour from the timestamp so the `where` clause can filter to outside business hours. Service account logins (Type 5) after hours are expected. Interactive or RDP logins (Type 2 or 10) from regular users after hours are not.

---

### Step 4 — Built the Windows Security Overview Dashboard

Navigated to Dashboards → Create New Dashboard, named it **Windows Security Overview**, and added four panels — one for each key search. Each panel was built using the Add Panel flow: select visualisation type, paste the search, set the time range, save to dashboard.

**📸 Screenshot — Failed Logins panel being configured (Bar Chart):**

![Failed Logins Bar Chart panel configuration](Splunk_FLI.png)

The panel uses a bar chart to show failed login counts by `Account_Name` over the last 24 hours. Bar charts work well here because the visual length immediately shows which accounts are seeing the most failures — no numbers needed to spot the outlier.

---

**📸 Screenshot — Login Activity Over Time panel (Line Chart):**

![Login Activity Over Time line chart panel configuration](Splunk_LAOT.png)

The `timechart count span=1h` command buckets login events into hourly intervals and plots them as a line chart. This view makes sudden spikes in login volume immediately obvious — a spike at 3am on a line chart is something you see before you even read the axis.

---

**📸 Screenshot — Account Lockouts panel (Events list):**

![Account Lockouts Last 7d events panel configuration](Splunk_ALO.png)

Lockouts are low-volume but high-signal. Displaying them as an events list with `_time`, `Account_Name`, and `Caller_Computer_Name` gives the full context for each lockout without needing aggregation — you want to see each individual event and where it came from.

---

**📸 Screenshot — Top Source IPs After Hours panel (Column Chart):**

![Top Source IPs After Hours column chart panel configuration](Splunk_TSIAH.png)

This panel combines the after-hours filter with a `stats count by Workstation_Name` to show which machines are generating after-hours login activity. A column chart makes it easy to see dominance at a glance — one workstation generating 300+ after-hours logins against a baseline of near-zero for everything else stands out immediately.

---

**📸 Screenshot — Completed Windows Security Overview dashboard:**

![Windows Security Overview dashboard](Splunk_Dashboard.png)

The finished dashboard shows all four panels live. The Failed Logins bar chart at the top immediately shows several accounts with elevated failure counts — one reaching nearly 100. The Login Activity Over Time line chart shows a sharp spike around 8pm, and the Top Source IPs After Hours column chart shows `AD-Lab` as the dominant source of after-hours activity. The Account Lockouts panel returned no events for the 7-day window, which in context means the failed login activity hadn't yet crossed the lockout threshold — an attacker being deliberate about staying under it.

---

### Step 5 — Created an Automated Alert

Built a scheduled alert that runs every 15 minutes and fires when any account has more than 10 failed logins in that window:

```
index=windows_logs sourcetype=WinEventLog:Security EventCode=4625
| stats count as failures by Account_Name
| where failures > 10
```

Alert configuration:
- **Name:** Potential Brute Force — High Failure Count
- **Type:** Scheduled, every 15 minutes
- **Trigger condition:** Number of Results is greater than 0
- **Action:** Add to Triggered Alerts

The threshold of 10 is a starting point. In a real environment you'd tune this based on observed false positive rates — too low and every user who mistyped their password triggers it, too high and you miss slow brute force attempts designed to stay under the noise floor.

---

## 💡 What I Took Away

The most valuable shift in this lab was moving from thinking about security events individually to thinking about them as patterns. A single failed login event is noise. Ten failed logins for the same account in five minutes is a signal. A hundred failed logins spread across twenty accounts in an hour is a different, more dangerous signal — a password spray, where an attacker is trying one common password against every account to avoid triggering lockouts on any single one. SPL is what lets you see the difference, and building the searches from scratch rather than copying them made the logic stick.

The dashboard also made something concrete that's usually abstract in documentation: the value of having everything in one view. Seeing the Failed Logins bar chart, the Activity Over Time spike, and the After-Hours source all on one screen at the same time is how an analyst starts building a mental picture of what's happening — without having to run three separate searches and hold the results in their head simultaneously.

The alert configuration reinforced that detection is a tuning problem, not a binary one. The threshold you set determines what you see and what you miss. Setting it too sensitive creates alert fatigue that causes real threats to get buried. Setting it too high means real attacks slip through. That tradeoff is something every SOC analyst lives with daily.

---

## 📎 Resources

- [Splunk Enterprise Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Splunk Universal Forwarder Docs](https://docs.splunk.com/Documentation/Forwarder/latest/Forwarder/Abouttheuniversalforwarder)
- [Windows Security Event Log Reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
