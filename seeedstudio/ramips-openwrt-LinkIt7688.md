# Insecure same - Password in seeedstudio ReSpeaker Core - Based On MT7688 Smart Speaker
## Overview
An insecure same - password vulnerability was identified in the seeedstudio ReSpeaker Core - Based On MT7688 smart speaker running the firmware version ramips - openwrt - latest - LinkIt7688 - squashfs - sysupgrade. The root user account uses a weak password (cracked as “root” using the John tool). This password is stored in the world - readable file /etc/shadow using MD5 - crypt hashing. It can be easily decrypted by the John tool and exploited. For example, attackers can gain unauthorized root access to the device through network - accessible services or the administrative interface.

## Vulnerability Details
+ **Vulnerability Type**: Insecure Default Password
+ **Affected Product**: seeedstudio ReSpeaker Core - Based On MT7688 and OpenWRT
+ **Affected Version**: ramips - openwrt - LinkIt7688
+ **Attack Type**: Remote
+ **Attack Vector**: Unauthorized login using the default password (root:root) via network - accessible services or the administrative interface
+ **Impact**:
    - Escalation of Privileges
    - Information Disclosure
    - Potential Code Execution
+ **Affected Component**: File, user authentication mechanism (/etc/shadow)
+ **CVE ID**: Pending (CVE application in progress)
+ **Discovered by**: xxricardoxkk (xxricardoxkk@gmail.com)
+ **Firmware**: [https://wiki.seeedstudio.com/ReSpeaker_Core/#resources](https://wiki.seeedstudio.com/ReSpeaker_Core/#resources)

## Discovery
The vulnerability was discovered by analyzing the firmware (ramips - openwrt - latest - LinkIt7688 - squashfs - sysupgrade.bin). The file was extracted from the squashfs - root directory. The MD5 - crypt hash of the root user's password was cracked using John, resulting in the password “root”. This weak password allows attackers to log in to the device's administrative interface or other services without additional vulnerabilities.

## Steps to Reproduce
1. Extract the firmware image ramips - openwrt - latest - LinkIt7688 - squashfs - sysupgrade.bin.
2. Locate the file in the extracted squashfs - root directory: squashfs - root/etc/shadow.
3. Use a password - cracking tool (e.g., John) to crack the MD5 - crypt hash of this user:
    - root:root:17120:0:99999:7:::\
![](https://github.com/XXRicardo/iot-cve/edit/main/seeedstudio/image/linkit7688_1.png)
4. Attempt to log in to the device's administrative interface or other network - accessible services using the cracked password.

## Impact
Attackers with network access to the device can:

+ Gain full administrative control by logging in with the root account (password: “root”).
+ Access sensitive configuration data, potentially exposing network details, modify device settings, or execute arbitrary code, leading to further network breaches.

