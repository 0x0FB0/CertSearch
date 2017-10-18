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

### Gathering aditional data

`./urlsearch.py example.com --debug 3>&1 1>&2 2>&3 | grep rsa_public_key -A 3`
