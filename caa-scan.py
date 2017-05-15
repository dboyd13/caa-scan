#!/usr/bin/env python
#
# caa-scan.py
# Copyright 2017 Darran Boyd
#
# dboyd13 [at @] gmail.com
#
# Licensed under the "Attribution-NonCommercial-ShareAlike" Vizsage
# Public License (the "License"). You may not use this file except
# in compliance with the License. Roughly speaking, non-commercial
# users may share and modify this code, but must give credit and 
# share improvements. However, for proper details please 
# read the full License, available at
#     http://vizsage.com/license/Vizsage-License-BY-NC-SA.html 
# and the handy reference for understanding the full license at 
#     http://vizsage.com/license/Vizsage-Deed-BY-NC-SA.html
#
# Unless required by applicable law or agreed to in writing, any
# software distributed under the License is distributed on an 
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, 
# either express or implied. See the License for the specific 
# language governing permissions and limitations under the License.

import hashlib
import dns.resolver
import datetime
import math
import sys
import json
import requests
import lz4tools
import os
import ConfigParser
from twython import Twython
from StringIO import StringIO
from zipfile import ZipFile
from urllib import urlopen

def get_cfg_option(config,section,name,default):
    if config.has_option(section,name):
        if type(default) == type(True): #Check if Boolean
            return config.getboolean(section,name)
        elif type (default) == type(4141): #Check if INT
            return config.getint(section,name)
        else: #treat as string
            return config.get(section,name)
    else:
        print '[*] Config: %s not specified in section %s, using default: %s' % (name,section,str(default))
        return default

def writeresults(vscansize, vcountcaa,vcountnocaa,vscanstart,vscanend):
    percentage = 0.0
    total = vcountcaa + vcountnocaa
    duration =  datetime.datetime.now() - vscanstart
    percentage = (vcountcaa / total) * 100
    f = open(CAA_HTML_FILE, 'w+')
    f.write('<p>Scan start: ' + vscanstart.strftime("%Y-%m-%d %H:%M") + '</p>')
    if vscanend != 0:
        f.write('<p>Scan end: ' + vscanend.strftime("%Y-%m-%d %H:%M") + '</p>')
    else:
        secondsremaining=(vscansize - total) / (total / duration.seconds)
        timeremaining=str(datetime.timedelta(seconds=secondsremaining))
        f.write('<p>Scan end: Still running -  %.3f%% complete, Performance: %.3f records per sec, Estimated: %s (HH:MM:ss) remaining</p>' % ((total / vscansize) * 100, total / duration.seconds, timeremaining))
    f.write('<p>Elapsed time (hh:mm:ss:ms): ' + str(duration) + '</p>')
    f.write('<hr>')
    f.write('<p>Scan size: ' + str(vscansize) + '</p>')
    f.write('<p>Total checked: ' + str(total) + '</p>')
    f.write('<p>CAA Present: ' + str(vcountcaa) + '</p>')
    f.write('<p>CAA NOT Present: ' + str(vcountnocaa) + '</p>')
    f.write('<hr>')
    f.write('<p>Percent CAA: ' + str(percentage) + '%</p>')
    f.close()

def downloadCensysData(CENSYS_API_URL, CENSYS_UID, CENSYS_SECRET, CENSYS_SERIES, CENSYS_FILE):
    print '[-] Censys API: Determining latest dataset for ' + CENSYS_SERIES
    res = requests.get(CENSYS_API_URL + "/data" + "/" + CENSYS_SERIES, auth=(CENSYS_UID, CENSYS_SECRET))
    if res.status_code != 200:
        print "error occurred: %s" % res.json()["error"]
        sys.exit(1)
    latestID=res.json()["results"]["latest"]["id"]
    latesttimestamp=res.json()["results"]["latest"]["timestamp"]
    print '[-] Censys API: Latest is ' + latesttimestamp
    res = requests.get(CENSYS_API_URL + "/data" + "/" + CENSYS_SERIES + "/" + latestID, auth=(CENSYS_UID, CENSYS_SECRET))
    downloadurl = res.json()["files"][CENSYS_FILE]["download_path"]
    sha256 = res.json()["files"][CENSYS_FILE]["sha256_fingerprint"]
    print '[-] Censys API: Latest is SHA256: ' + sha256

    local_sha256 = hashlib.sha256()
    try:
        with open(work_dir + CENSYS_FILE + '.csv')as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                local_sha256.update(data)
        print '[-] Local file SHA256: ' + local_sha256.hexdigest()
    except:
        print '[-] No existing file present'

    if local_sha256.hexdigest() == sha256:
        print '[-] Local file hash matches - already have the latest dataset'
    else:
        print '[-] Downloading: ' + CENSYS_SERIES
        r = requests.get(downloadurl)
        if r.status_code == 200:
            with open(work_dir + CENSYS_FILE + ".lz4", 'wb') as f:
                for chunk in r:
                    f.write(chunk)
        print '[-] Download complete, wrote to: ' + CENSYS_FILE + '.lz4'
        print '[-] Decompressing: ' + CENSYS_FILE + '.lz4'
        contents = lz4tools.open(work_dir + CENSYS_FILE +'.lz4').read()
        f = open(work_dir + CENSYS_FILE + '.csv', 'w')
        f.write(contents)
        f.write('\n') #Need this to make the hashes match
        f.close()
        print '[-] Decompression complete, wrote to: ' + CENSYS_FILE + '.csv'

#######################
#-------MAIN----------#
#######################

#Check for command arguments, else use 'config.ini'

if len(sys.argv) > 1:
    config_file = sys.argv[1]
    print '[-] Config: file %s specified as argument, will try use that' % (sys.argv[1])
else:
    print '[-] Config: No config file specified, will try default - config.ini'
    config_file = 'config.ini'

#Load the config file
work_dir = os.path.dirname(os.path.realpath(__file__)) + '/' #Get the directory that this script is in
Config = ConfigParser.ConfigParser()
Config.read(config_file)

try:
    with open(work_dir + config_file) as f:
        Config.readfp(f)
except IOError:
     print '[!] Config: file %s not present' % (config_file)
     exit(1)

#Parse CAA Scan config
CAA_SCAN_LIMIT = get_cfg_option(Config,'caa-scan','CAA_SCAN_LIMIT', 0) #Limit scan to X records, set to 0 to run the full set from csv file
CAA_PRINT_STDOUT = get_cfg_option(Config,'caa-scan','CAA_PRINT_STDOUT', True)#Show each result in STDOUT, enable for debug only
CAA_HTML_OUTPUT = get_cfg_option(Config,'caa-scan','CAA_HTML_OUTPUT', False) #Write interim and final results to HTML file?
CAA_HTML_FILE = get_cfg_option(Config,'caa-scan','CAA_HTML_FILE','/var/www/results.html') #HTML file to write too (if enabled)
CAA_HTML_REPORT_FREQUENCY = get_cfg_option(Config,'caa-scan','CAA_HTML_REPORT_FREQUENCY', 500) #Report interim status to HTML every X records
CAA_VALID_RECORD_OUTPUT = get_cfg_option(Config,'caa-scan','CAA_VALID_RECORD_OUTPUT', False) #Output valid CAA records to text file?
CAA_VALID_RECORD_FILE_PREFIX = get_cfg_option(Config,'caa-scan','CAA_VALID_RECORD_FILE_PREFIX','caarecords') #File name prefix to write valid CAA reco

#Parse Censys config
CENSYS_API_URL = get_cfg_option(Config,'censys','CENSYS_API_URL','https://www.censys.io/api/v1') #Censys.io API endpoint
CENSYS_UID = get_cfg_option(Config,'censys','CENSYS_UID','') #Censys.io API UID
CENSYS_SECRET = get_cfg_option(Config,'censys','CENSYS_SECRET','') #Censys.io API SECRET
CENSYS_SERIES = get_cfg_option(Config,'censys','CENSYS_SERIES','443-https-tls-alexa_top1mil') #Censys.io SERIES to query
CENSYS_FILE = get_cfg_option(Config,'censys','CENSYS_FILE','alexa-results') #Censys.io RAW FILE to download

#Parse Twitter config
TWITTER_OUTPUT = get_cfg_option(Config,'twitter','TWITTER_OUTPUT', False) #Auto-tweet the results?
TWITTER_APP_KEY = get_cfg_option(Config,'twitter','TWITTER_APP_KEY','') #Twitter APP Key
TWITTER_APP_SECRET = get_cfg_option(Config,'twitter','TWITTER_APP_SECRET','') #Twitter APP SECRET
TWITTER_TOKEN = get_cfg_option(Config,'twitter','TWITTER_TOKEN','') #Twitter OAUTH Token
TWITTER_TOKEN_SECRET = get_cfg_option(Config,'twitter','TWITTER_TOKEN_SECRET','') #Twitter OAUTH SECRET
TWITTER_HASH_TAGS = get_cfg_option(Config,'twitter','TWITTER_HASH_TAGS','#CAA #DNS') #Twitter hash tags to append to tweet

#Set initial variable values
countcaa=0.0
countnocaa=0.0
scansize=0.0
scanprogress=0.0
reportingcounter=CAA_HTML_REPORT_FREQUENCY
scanstart=datetime.datetime.now()
caafilename  = CAA_VALID_RECORD_FILE_PREFIX  + '-'  + scanstart.strftime("%Y-%m-%d") + '.txt'

# Download latest dataset from Censys.io and decompress lz4
downloadCensysData(CENSYS_API_URL, CENSYS_UID, CENSYS_SECRET, CENSYS_SERIES, CENSYS_FILE)

# Determine the count of hosts available#
with open(work_dir + 'alexa-results.csv') as f: #Open file
    for record in f: #Determine the amount of total records
        scansize += 1

#Update scansize to match CAA_SCAN_LIMIT set
if CAA_SCAN_LIMIT != 0:
    scansize = min(scansize,CAA_SCAN_LIMIT)

print "[-] Running against %d HTTPS enabled of Alexa 1m sites" % (scansize)

#Open a file handle to record CAA responses
if CAA_VALID_RECORD_OUTPUT == True:
    caafile = open(work_dir + caafilename,'w+')

#The actual scan - lets do this thing...
with open(work_dir + 'alexa-results.csv') as f: #Open file (again)
    for line in f: #Loop for each line
        if (CAA_SCAN_LIMIT != 0 and countcaa + countnocaa >= CAA_SCAN_LIMIT): #Check CAA_SCAN_LIMITs and break loop if CAA_SCAN_LIMIT reached
            break
        if (countcaa + countnocaa == reportingcounter and CAA_HTML_OUTPUT == True): #Check if it's time for an interim report
            writeresults(scansize, countcaa,countnocaa,scanstart,0)
            reportingcounter += CAA_HTML_REPORT_FREQUENCY
        domain = line.split(',')[1]  #Grab the 2nd field containing the domain name
        domain = domain.rstrip() #Strip whitespace and new line chars
        try:
            content = ""
            caarecords = dns.resolver.query(domain,'CAA') #Do a CAA query on domain
            if CAA_PRINT_STDOUT == True:
               for record in caarecords:
                    content = content + "," + str(record)
                    print domain + "," + content
                    if CAA_VALID_RECORD_OUTPUT == True:
                        caafile.write(domain  + content + "\n")
            countcaa += 1
        except dns.exception.DNSException:
            if CAA_PRINT_STDOUT:
                print domain + "," + "NO CAA RECORD"
            countnocaa += 1

#Scan is finished
if CAA_VALID_RECORD_OUTPUT:
    caafile.close()
#get date/time and report
scanend=datetime.datetime.now()

print "[-] Stats"
print "Total checked: " + str(countcaa + countnocaa)
print "CAA Present: " + str(countcaa)
print "CAA NOT Present: " + str(countnocaa)

#Write final results to HTML file (if enabled)
if CAA_HTML_OUTPUT == True:
    writeresults(scansize, countcaa,countnocaa,scanstart,scanend)

#Tweet results (in enabled)
if TWITTER_OUTPUT == True:
    percentage = (countcaa / (countcaa + countnocaa)) * 100
    tweet = 'CAA adoption is at %.3f%% for HTTPS enabled Alexa Top 1m sites. Scan total: %d | CAA records: %d %s' % (percentage, countcaa+countnocaa, countcaa, TWITTER_HASH_TAGS)
    twitter = Twython(TWITTER_APP_KEY,TWITTER_APP_SECRET, TWITTER_TOKEN, TWITTER_TOKEN_SECRET)
    twitter.update_status(status=tweet)
    print "[-] Tweeted: %s" % (tweet)
print "[-] Done."
