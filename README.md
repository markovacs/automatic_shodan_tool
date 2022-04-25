# 1. Objective:
Create an automatic threat intelligence tool to check all the servers and domains of Dekra connected to the internet for possible vulnerabilities or insecurities. Part of the automation is to create a documentation tool reporting details of vulnerabilities and insecurities of all domains. 
# 2. Tools:
- Shodan API – for checking vulnerabilities 
- Python – for automating processes and creating a reporting tool
# 3. Vulnerabilities:
## 3.1 SSL and TLS vulnerabilities  

||**Name**|**Vulnerable Versions**|**Commands**|
| :- | :-: | :-: | :-: |
|**SSL filters ([Vulnerabilities](https://pleasantpasswords.com/info/pleasant-password-server/f-best-practices/secure-and-harden-your-server-environment/encryption-protocols-and-ciphers))**|SSL versions|SSL2, SSL3, TLS1.0, TLS1.1, TLS1.2|ssl.version…|
||Insecure ciphers|DES, 3DES, and RC4, AES with CBC chaining mode|ssl.cipher.version…|
||RSA key size|DH key sizes < 2048 or ECDH key size < 224|ssl.cert.pubkey.bits…|
## 3.2 Secure Headers vulnerabilities according to OWASP 
### 3.2.1 Secure headers to check if missing

|**Name**|**Attack vectors**|
| :-: | :-: |
|HTTP Strict Transport Security|downgrade attacks and cookie hijacking|
|X-Frame-Options|clickjacking|
|X-Content-Type-Options|MIME-sniffing|
|Content-Security-Policy|cross-site scripting and other cross-site injections.|
|X-Permitted-Cross-Domain-Policies|XML document that grants a web client permission to handle data across domains|
|Clear-Site-Data|Possible mishandling of cookies and cache|
|Referrer-Policy|The Referrer-Policy HTTP header governs which referrer information, sent in the Referrer header, should be included with requests made|
|Cross-Origin-Embedder-Policy|COEP prevents a document from loading any cross-origin resources that don’t explicitly grant the document permission|
|Cross-Origin-Opener-Policy|COOP allows you to ensure a top-level document does not share a browsing context group with cross-origin documents|
|Cross-Origin-Resource-Policy|CORP allows to define a policy that lets web sites and applications opt into protection against certain requests from other origins|
|Cache-Control|Cache-Control is the recommended way to define the caching policy|
### 3.2.2 Secure headers to avoid using

|**Name**|**Check**|
| :-: | :-: |
|X-XSS-Protection|X-XSS-Protection: 0|
|Public-Key-Pins|Avoid using at all costs|
|Expect-CT|Still used in few browsers, but deprecated |
## 3.3 Common vulnerabilities and exposures
With shodan exploits I can check whether the server versions have any CVE-s available. This might not mean that the device is exploitable, but we have to make sure that we use the latest (or a safe) version.
# 4. Reporting:

The tool will create the neccesary csv files, which can be exported to a power bi report.


