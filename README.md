# CertSearch
Certificate search and monitoring through Censys API

## Usage
`./certsearch.py <domain> [options]`

  `--debug   Print out raw API data`
  
  `--init    Initialize certificate store (automatic if DATAFILE doesn't exist)`
  
  `--batch   Don't ask for user input, auto-update DATAFILE`
  
  `--alert   Send mail notification of certificate change`
  
## Config
|Glbal variables|Values                              |Description         |
|---------------|------------------------------------|--------------------|
|UID            |00000000-0000-0000-0000-000000000000|CENSYS API UID      |
|SECRET         |XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX    |CENSYS API SECRET   |
|DATAFILE       |/tmp/certsearch.json                |CERTIFICATES STORAGE|
|SENDER_FILE    |certsearch@example.com              |ALERT SENDER        |
|RECIPENT_ADDR  |monitoring@example.com              |ALERT RECIPIENT     |
|MAIL_SRV       |mail.example.com                    |ALERT SERVER        |

## Examples

### Search for certificates by domain

`./urlsearch.py example.com`

### Monitor for new or changed certificates for domain (ex. cron)

`./urlsearch.py example.com --batch --alert`

### Gathering additional data

`./urlsearch.py example.com --debug 3>&1 1>&2 2>&3 | grep rsa_public_key -A 3`

### Example output

```
root@postern ⚡./certsearch.py example.com


[i] Addresses found for query 'subject_alt_name.dns_names example.com':


-----------------------------------------------------------------------------------------------------------------------------------------------------------
[1] Address: 23.254.204.101 (cns40005.hostwindsdns.com) Services: 80/http 993/imaps 995/pop3s 110/pop3 21/ftp 143/imap 53/dns 443/https 22/ssh
-----------------------------------------------------------------------------------------------------------------------------------------------------------


[i] Certificates found for address: 23.254.204.101

Fingerprint:	b08495f0de0a4cc76de33f1f4355404c67ea9a41596174aa7a884901a9f3205d
Subject:	CN=example.com
Issuer:		CN=example.com

[i] Validity for ROOT CA:
Issued for:	www.example.com example.com mail.example.com
google_ct_primary: False
nss: False
apple: False
microsoft: False

[i] Validity dates:

Added to database 195 days ago
Updated in database 25 days ago

Validity start:	2017-04-04 15:02:51
Expiration date:	2018-04-04 15:02:51 - OK!

Tags:	unknown self-signed unexpired


```
