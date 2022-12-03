#!/usr/bin/python
#Inspired by Cristi Zot's Udemy course, "Python for Penetration Testers"
#Recon GeoIP information derived from ipinfo.io

import sys
import requests
import socket
import json

#if a value is not submitted, then the below usage will be shown.
if len(sys.argv) < 2: 
    print("Usage: " + sys.argv[0] + "<url>")
    sys.exit(1)

req = requests.get("https://"+sys.argv[1])
print("\nHeader Info:\n"+str(req.headers))  #header grabbing

gethostby_ = socket.gethostbyname(sys.argv[1]) #get hostname
#print("\nThe Ip address of " +sys.argv[1]+ " is: " +gethostby_ + "\n")

#Get GeoIP using IPinfo.io API
req_two = requests.get("https://ipinfo.io/"+gethostby_+"/json")
resp_ = json.loads(req_two.text)
print("\nGeoIP Info: ")
print("IP: "+resp_['ip'])
print("Hostname: "+resp_['hostname'])
print("Location: "+resp_['loc'])
print("Region: "+resp_['region'])
print("City: "+resp_['city'])
print("Country: "+resp_['country'])
print("Postal Code: "+resp_['postal'])
print("Time Zone: "+resp_['timezone'])
print("Organization: "+resp_['org'])


