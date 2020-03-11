import sys
import os
import glob
import re
import requests
import json
import dns.resolver
import hashlib
import time
import twitter

ipinfo_url = 'http://ipinfo.io/'
ipinfo_token = '?token=[your ipinfo.io token here]'
vti_api_key = '[your VirusTotal API key here]'
vti_upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
vti_comment_url = 'https://www.virustotal.com/vtapi/v2/comments/put'
bamfdetect = '/home/ubuntu/src/bamfdetect/bamfdetect'
pastes_dir = '/home/ubuntu/pastes/'
done_dir = '/home/ubuntu/pastes/done/'
rsrch_dir = '/home/ubuntu/pastes/research/'
logfile = pastes_dir + 'c2out.json'
DOMAIN_REGEX = re.compile('([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]', re.IGNORECASE)
IPV4_REGEX = re.compile('[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]')
myResolver = dns.resolver.Resolver()
myResolver.nameservers = ['172.30.0.2', '8.8.8.8']
twitter_config = {}
exec(open("/home/ubuntu/twitter_config.py").read(), twitter_config)


def filehash(filename):
    with open(filename, 'rb') as f:
        raw = f.read()
    sha256hash = hashlib.sha256(raw).hexdigest()
    return sha256hash


def BAMFrun(filename):
    runcmd = bamfdetect + " " + filename
    bamfout = os.popen(runcmd).read().rstrip(',\n')
    if len(bamfout) == 0:
        with open(filename, 'rb') as f:
            raw = f.read()
        f.close()
        return "None","None"
    try:
        result = json.loads(bamfout)
        for filekey in result.keys():
            type = result[filekey]["type"]
            try:
                c2 = result[filekey]["information"]["c2_uri"]
            except:
                c2 = ""
                for a in result[filekey]["information"]["c2s"]:
                    c2+=a["c2_uri"]+","
        return type,c2
    except:
        return "None","None"


def tweet(status):
    try:
        MyTwitter = twitter.Api(access_token_key=twitter_config["access_key"],
                                access_token_secret=twitter_config["access_secret"],
                                consumer_key=twitter_config["consumer_key"],
                                consumer_secret=twitter_config["consumer_secret"])
        results = MyTwitter.PostUpdate(status)
        print("updated status: %s" % status)
    except:
        print(status)
        print("Error posting to Twitter!")
        sys.exit(1)


def vt_upload(file):
    params = {'apikey': vti_api_key}
    files = {'file': (file, open(file, 'rb'))}
    r = requests.post(vti_upload_url, files=files, params=params)
    response = r.json()


def vt_comment(comment,filehash):
    params = {"resource": filehash, "comment": comment, "apikey": vti_api_key}
    try:
        r = requests.post(vti_comment_url, params=params)
        response = r.json()
    except:
        print(r.content)
        print("Error submitting comment to VirusTotal!")


def isip(string):
    if IPV4_REGEX.search(string) and not string.startswith("127.0.0.") and not string.startswith("0.") and not string.startswith("10.") and not string.startswith("192.168."):
        return True


def getipinfo(ipaddr):
    if isip(ipaddr):
        url = ipinfo_url + ipaddr + ipinfo_token
        r = requests.get(url)
        if r.status_code == 200:
            response = r.json()
            loc = response["loc"]
            city = response["city"]
            region = response["region"]
            try:
                hostname = response["hostname"]
            except:
                hostname = ''
            country = response["country"]
            org = response["org"]
            try:
                postal = response["postal"]
            except:
                postal = ''
            return loc,city,region,hostname,country,org,postal
        else:
            print("Problem connecting to: " + url)
            print("Status code: " + str(r.status_code))
            print(r.content)
            sys.exit(1)
    else:
        print(ipaddr + ' is not an IP address')
        sys.exit(1)


def recordc2(c2):
    for a in c2.split(','):
        try:
            ipaddr = IPV4_REGEX.search(a).group(0)
            fqdn = ""
        except:
            ipaddr = "err"
        if ipaddr == "err":
            try:
                fqdn = DOMAIN_REGEX.search(a).group(0)
            except:
                fqdn = "err"
            if fqdn != "err":
                try:
                    ipaddr = str(myResolver.query(fqdn, 'A')[0])
                except:
                    ipaddr = "err"
                    loc = "err"
                    city = "err"
                    region = "err"
                    hostname = "err"
                    country = "err"
                    org = "err"
                    postal = "err"
        if ipaddr != "err" and isip(ipaddr):
            loc,city,region,hostname,country,org,postal = getipinfo(ipaddr)
            logentry = {
                'paste':paste,
                'hash':sha256hash,
                'type':type,
                'c2':c2,
                'fqdn':fqdn,
                'ipaddr':ipaddr,
                'loc':loc,
                'city':city,
                'region':region,
                'hostname':hostname,
                'country':country,
                'org':org,
                'postal':postal
            }
            jlo = json.dumps(logentry, ensure_ascii=False)
            with open(logfile, 'a+') as f:
                f.write(jlo + '\n')
        else:
            print("Error: RFC1918 or unparsed IP address (" + ipaddr + ")")


ls = pastes_dir + '*.exe'
exelist = glob.glob(ls)
for filename in exelist:
    base = os.path.basename(filename)
    paste = os.path.splitext(base)[0]
    sha256hash = filehash(filename)
    type,c2 = BAMFrun(filename)
    stored_file = done_dir + base + "_" + sha256hash
    stored_file = done_dir + base + "_" + sha256hash
    if not os.path.isfile(stored_file) and not (type == 'None'):
        vt_upload(filename)
        time.sleep(15)
        comment = type + " found at https://pastebin.com/raw/" + paste + " SHA256: " + sha256hash + " C2: " + c2
        if len(comment) > 500:
            comment = comment[:500]
        vt_comment(comment,sha256hash)
        c2safe = c2.replace(".", "[.]")
        message = '#' + type + " found at https://pastebin.com/raw/" + paste + " SHA256: " + sha256hash + " C2: " + c2safe
        if len(message) > 280:
            message = message[:280]
        tweet(message)
        new_filename = stored_file
        os.rename(filename, new_filename)
        recordc2(c2)
    elif (type == 'None') and not os.path.isfile(stored_file):
        new_filename = rsrch_dir + base + "_" + sha256hash
        os.rename(filename, new_filename)
    else:
        os.remove(filename)
