import sys
import os
import glob
import re
import requests
import json
import urllib
import urllib2
import dns.resolver
import hashlib
import time
from twitter import *

vti_api_key = ''
vti_upload_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
vti_comment_url = 'https://www.virustotal.com/vtapi/v2/comments/put'
bamfdetect = '/home/ubuntu/src/bamfdetect/bamfdetect'
pastes_dir = '/home/ubuntu/pastes/'
done_dir = '/home/ubuntu/pastes/done/'
rsrch_dir = '/home/ubuntu/pastes/research/'
logfile = pastes_dir + 'c2out.json'
DOMAIN_REGEX = re.compile('([a-z0-9][a-z0-9\-]{0,61}[a-z0-9]\.)+[a-z0-9][a-z0-9\-]*[a-z0-9]', re.IGNORECASE)
IPV4_REGEX = re.compile('[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]\.[1-2]?[0-9]?[0-9]')
ipinfo_url = 'http://ipinfo.io/'
myResolver = dns.resolver.Resolver()
myResolver.nameservers = ['172.30.0.2', '8.8.8.8']
config = {}
execfile("/home/ubuntu/twitter_config.py", config)

def BAMFrun(file):
    runcmd = bamfdetect + " " + file
    bamfout = os.popen(runcmd).read().rstrip(',\n')
    try:
        result = json.loads(bamfout)
        for filekey in result.keys():
            type = result[filekey]["type"]
            hash = result[filekey]["postprocessor"]["sha256"]
            try:
                c2 = result[filekey]["information"]["c2_uri"]
            except:
                c2 = ""
                for a in result[filekey]["information"]["c2s"]:
                    c2+=a["c2_uri"]+","
        return type,hash,c2
    except:
        with open(file) as f:
            raw = f.read()
        f.close()
        m = hashlib.md5()
        m.update(raw)
        hash = m.hexdigest()
        return "None",hash,"None"

def tweet(status):
    try:
        twitter = Twitter(auth = OAuth(config["access_key"], config["access_secret"], config["consumer_key"], config["consumer_secret"]))
        results = twitter.statuses.update(status = status)
        print "updated status: %s" % status
    except:
        print status
        print "Error posting to Twitter!"
        sys.exit(1)

def vt_upload(file):
    params = {'apikey': vti_api_key}
    files = {'file': (file, open(file, 'rb'))}
    r = requests.post(vti_upload_url, files=files, params=params)
    response = r.json()
#  try:
#    response = r.json()
#  except:
#    print r.content

def vt_comment(comment,md5):
    params = {"resource": md5,
                      "comment": comment,
                      "apikey": vti_api_key}
    data = urllib.urlencode(params)
    req = urllib2.Request(vti_comment_url, data)
    r = urllib2.urlopen(req)

def isip(string):
        if IPV4_REGEX.search(string) and string != "127.0.0.1" and not string.startswith("10.") and not string.startswith("192.168."):
                return True

def getipinfo(ipaddr):
        if isip(ipaddr):
                url = ipinfo_url + ipaddr
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
                      print "Problem connecting to: " + url
                      sys.exit(1)
        else:
                print ipaddr + ' is not an IP address'
                sys.exit(1)

ls = pastes_dir + '*.exe'
logfile = open(logfile, 'a+')
exelist = glob.glob(ls)
for filename in exelist:
    base = os.path.basename(filename)
    paste = os.path.splitext(base)[0]
    type,hash,c2 = BAMFrun(filename)
    stored_file = done_dir + base + "_" + hash
    stored_file = done_dir + base + "_" + hash
    if not os.path.isfile(stored_file) and not (type == 'None'):
        vt_upload(filename)
        c2safe = c2.replace(".", "[.]")
        message = type + " found at https://pastebin.com/" + paste + " SHA256: " + hash + " C2: " + c2safe
        if len(message) > 280:
            message = message[:280]
        tweet(message)
        time.sleep(30)
        comment = type + " found at https://pastebin.com/" + paste + " SHA256: " + hash + " C2: " + c2
        vt_comment(comment,hash)
        new_filename = stored_file
        os.rename(filename, new_filename)
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
                    'paste':str(paste),
                    'hash':str(hash),
                    'type':str(type),
                    'c2':str(c2),
                    'fqdn':str(fqdn),
                    'ipaddr':str(ipaddr),
                    'loc':(loc).encode('utf-8'),
                    'city':(city).encode('utf-8'),
                    'region':(region).encode('utf-8'),
                    'hostname':str(hostname),
                    'country':str(country),
                    'org':str(org),
                    'postal':str(postal)
                }
                jlo = json.dumps(logentry)
                logfile.write(jlo + "\n")
            else:
                print("Error: RFC1918 or unparsed IP address (" + ipaddr + ")")
    elif (type == 'None') and not os.path.isfile(stored_file):
        new_filename = rsrch_dir + base + "_" + hash
        os.rename(filename, new_filename)
    else:
        os.remove(filename)
