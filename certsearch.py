#!/usr/bin/python

import os, sys, json, requests, datetime, base64, difflib, socket, smtplib
from email.mime.text import MIMEText

debug = 0
init = 0
batch = 0
alert = 0

if len(sys.argv) < 2:
    print "[!] Usage: ./%s <domain> [OPTS]" % sys.argv[0]
    exit(1)
else:
    if '--debug' in sys.argv:
        debug = 1
    if '--init' in sys.argv:
        init = 1
    if '--batch' in sys.argv:
        batch = 1
    if '--alert' in sys.argv:
        alert = 1
    domain = str(sys.argv[1])

# --- USER CONFIG -----------------------------------------
UID     =   "00000000-0000-0000-0000-000000000000" # CENSYS API UID
SECRET  =   "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"     # CENSYS API SECRET
DATAFILE =   "/tmp/certsearch.json"                # CERTIFICATES STORAGE
SENDER_ADDR = "certsearch@example.com"             # ALERT SENDER
RECIPIENT_ADDR = "monitoring@example.com"          # ALERT RECIPIENT
MAIL_SRV = "mail.example.com"                      # ALERT SERVER
# ---------------------------------------------------------

if not os.path.exists(DATAFILE):
    init = 1

API_URL =   "https://www.censys.io/api/v1"
HEADR = {'Content-type': 'application/json', 'Accept': 'text/plain'}
QUERY = {'query': '443.https.tls.certificate.parsed.extensions.subject_alt_name.dns_names: '+domain}
now = datetime.datetime.now()
cnt = 1

res = requests.post(API_URL + "/search/ipv4", auth=(UID, SECRET), data=json.dumps(QUERY), headers=HEADR)
addr_data = res.json()
if 'results' not in addr_data:
    print "\033[31m\033[1m[ERR] API Connection error!"
    print repr(res)
    print "\033[0m"
    exit(1)

if debug == 1:
    print "\033[33m"+"+"*50
    print json.dumps(addr_data, indent=4)
    print "\033[33m"+"+"*50+"\033[0m"

cert_list = {}
cached_data = {}

if init != 1:
    with open(DATAFILE, 'r') as db:
        cached_data = json.loads(db.read())

def diff_json(exp, act):
    clean = list()
    exp=exp.replace(',', '')
    act=act.replace(',', '')
    exp=exp.replace(' \n', '\n')
    act=act.replace(' \n', '\n')
    expected = exp.splitlines(1)
    actual = act.splitlines(1)
    expected.sort()
    actual.sort()
    diff = difflib.ndiff(expected, actual)
    for l in diff:
        if any(l[0] in c for c in ['+','-','?']):
            if l[0] == '+':
                color = '\033[31m'
            elif l[0] == '-':
                color = '\033[32m'
            else:
                color = '\033[33m'
            clean.append(color+l+'\033[0m')
    return '\n'.join(clean)


print "\n\033[1m[i] Addresses found for query 'subject_alt_name.dns_names "+domain+"':\033[0m\n\n" 
for e in addr_data['results']:
    try:
        hostname, alias, addrl = socket.gethostbyaddr(e['ip'])
    except Exception:
        hostname = "reverse.dns.failed"
    banner = "\033[33m\033[1m[%s] Address: %s (%s) Services: %s\033[0m" % (str(cnt), e['ip'], hostname, ' '.join(e['protocols']) )
    print "\033[33m\033[1m"+"-"*len(banner)+"\033[0m"+"\n"+banner+"\n"+"\033[33m\033[1m"+"-"*len(banner)+"\033[0m"
    res = requests.get(API_URL + "/view/ipv4/"+ str(e['ip']),  auth=(UID, SECRET), headers=HEADR)
    ip_data = res.json()
    for key in ip_data:
        if 'https' in ip_data[key] and key != "tags":
            datac = ip_data[key]['https']['tls']['certificate']
            cert_list.update({str(e['ip']):base64.b64encode(json.dumps(datac, indent=4))})
            print ""
            if e['ip'] in cached_data:
                jdiff = diff_json(base64.b64decode(cached_data[e['ip']]), json.dumps(datac, indent=4))
                if len(jdiff) == 0:
                    print "\033[32m\033[1m[i] Integrity OK\033[0m"
                else:
                    print "\033[43m\033[31m[WARN] Certificate data have changed!\033[0m\n"
                    print jdiff
                    print ""
                    if batch == 1 and alert == 1:
                        try:
                            init = 1
                            text = "Certificate for %s (%s) have changed!\n"
                            text += "Query: subject_alt_name.dns_names %s\n\n" % domain
                            text += "Certificate diff:"
                            text += jdiff
                            text += "\n\n"
                            msg = MIMEText(text)
                            msg['Subject'] = "CertWatch certificate change alert"
                            msg['From'] = SENDER_ADDR
                            msg['To'] = RECIPIENT_ADDR
                            s = smtplib.SMTP(MAIL_SRV)
                            s.sendmail(SENDER_ADDR, [RECIPIENT_ADDR], msg.as_string())
                            s.quit()
                            print "\033[33m[i] Alert email sent.\033[0m"
                        except Exception:
                            print "\033[31m\033[1m[ERR] Email client error!\033[0m"
                    elif batch == 1:
                        init = 1
                    else:
                        ask = str(raw_input("\033[43m\033[31mDo you want to overwrite?(N/y):\033[0m "))
                        if ask == 'y' or ask == 'Y':
                            init = 1

            print "\n\033[34m\033[1m[i] Certificates found for address: %s\033[0m\n" % str(e['ip'])
            print "\033[34mFingerprint:\033[0m\t%s" % datac['parsed']['fingerprint_sha256']
            print "\033[34mSubject:\033[0m\t%s" % datac['parsed']['subject_dn']
            print "\033[34mIssuer:\033[0m\t\t%s" % datac['parsed']['issuer_dn']
            print "\n\033[34m[i] Validity for ROOT CA:\033[0m"
            cert_info_raw = requests.get(API_URL + "/view/certificates/"+str(datac['parsed']['fingerprint_sha256']), auth=(UID, SECRET), headers=HEADR)
            cert_info = cert_info_raw.json()
            print "\033[34mIssued for:\033[0m\t\033[1m%s\033[0m" % ' '.join(cert_info['parsed']['names'])
            for ca in cert_info['validation']:
                if str(cert_info['validation'][ca]['valid']) == 'False':
                    color = "\033[31m"
                else:
                    color = "\033[32m"
                print "\033[34m%s:\033[0m %s%s\033[0m" % (ca, color, cert_info['validation'][ca]['valid'])
            print "\n\033[34m[i] Validity dates:\033[0m\n"
            try:
                added_at = datetime.datetime.strptime(cert_info['metadata']['added_at'], '%Y-%m-%dT%H:%M:%S+00:00')
            except Exception:
                added_at = "NA"
            try:
                updated_at = datetime.datetime.strptime(cert_info['metadata']['updated_at'], '%Y-%m-%dT%H:%M:%S')
            except Exception:
                updated_at = "NA"
            if added_at != "NA":
                delta_added = now - added_at
                print "Added to database %s days ago" % str(delta_added.days)
                if delta_added.days < 1:
                    print "\033[43m\033[31m[WARN] Entry just added to the database!\033[0m"
            if updated_at !="NA":
                delta_updated = now - updated_at
                print "Updated in database %s days ago" % str(delta_updated.days)
                if delta_updated.days < 1:
                    print "\033[43m\033[31m[WARN] Entry was just updated in the database!\033[0m"
            print ""
            validfrom = datetime.datetime.strptime(cert_info['parsed']['validity']['start'], '%Y-%m-%dT%H:%M:%SZ')
            print "Validity start:\t%s" % str(validfrom)
            expire = datetime.datetime.strptime(cert_info['parsed']['validity']['end'], '%Y-%m-%dT%H:%M:%SZ')
            if expire < now:
                print "Expiration date:\t\033[41m%s - Expired!\033[0m" % str(expire)
            else:
                print "Expiration date:\t\033[42m%s - OK!\033[0m" % str(expire)
            print ""
            print "\033[35mTags:\t\033[0m\033[45m%s\033[0m\n\n" % '\033[0m \033[45m'.join(cert_info['tags'])
            print "\033[0m"
            cnt = cnt+1
            if debug == 1:
                print "\033[33m"+"+"*50
                print json.dumps(cert_info, indent=4)
                print "+"*50+"\033[0m"
if init == 1:
    with open(DATAFILE, 'w+') as db:
        db.write(json.dumps(cert_list, indent=4))
