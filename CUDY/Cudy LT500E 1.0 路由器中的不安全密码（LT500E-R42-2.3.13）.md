# Insecure Password in Cudy LT500E 1.0 Router (LT500E-R42-2.3.13)
## Overview
An insecure password vulnerability was identified in the Cudy LT500E 1.0 Router running firmware version LT500E-R42-2.3.13-20250221-111145-flash. The root user account uses the default password “admin”. This password is stored in the file using MD5-crypt hashing. This weak password can be easily decrypted using the John tool and can also be directly used to log in to the router's Web interface or other network-accessible services, enabling attackers to gain unauthorized root access. 

## Vulnerability Details
+ **Vulnerability Type**: Insecure Default Credentials
+ **Affected Product**: Cudy LT500E 1.0 Router
+ **Affected Version**: LT500E-R42-2.3.13
+ **Attack Type**: Remote
+ **Attack Vector**: Unauthorized login using the default password (root:admin) via network-accessible services or the administrative interface 
+ **Impact**:
    - Escalation of Privileges 
    - Information Disclosure 
    - Potential Code Execution
+ **Affected Component**: File, user authentication mechanism (/etc/shadow)
+ **CVE ID**: Pending (CVE application in progress)
+ **Discovered by**: xxricardoxkk (xxricardoxkk@gmail.com)
+ **Firmware**: [https://www.cudy.com/zh-cn/pages/download-center/lt500e-1-0](https://www.cudy.com/zh-cn/pages/download-center/lt500e-1-0)

## Discovery
The vulnerability was discovered by analyzing the firmware (LT500E-R42-2.3.13-20250221-111145-flash.bin). The file was extracted from the squashfs-root directory. The MD5-crypt hash of the root user's password was cracked using John, resulting in the password “admin”. This weak password allows attackers to log in to the device's administrative interface or other services without additional vulnerabilities. 

## Steps to Reproduce
1. Extract the firmware image LT500E-R42-2.3.13-20250221-111145-flash.bin. 
2. Locate the file in the extracted squashfs-root directory: squashfs-root/etc/shadow. 
3. Use a password-cracking tool (e.g., John) to crack the MD5-crypt hash of this user: 
    - root:admin:17495:0:99999:7:::
4. Attempt to log in to the device's administrative interface or other network-accessible services using the cracked password.

## Impact
Attackers with network access to the device can:

+ Gain full administrative control by logging in with the root account (password: “admin”). 
+ Access sensitive configuration data, potentially exposing network details, modify device settings, or execute arbitrary code, leading to further network breaches.



