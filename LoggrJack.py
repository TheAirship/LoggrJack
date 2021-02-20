#!/usr/bin/env python3

"""LoggrJack - Simplify Text-Based Log Analysis

LoggrJack is a command line log parser that allows incident responders and security professionals
to quickly extract meaningful data from long, text-formatted logs (e.g. csv, txt). The ultimate
goal of the LoggrJack project is to allow for an at-a-glance review of activity logs
for different systems and applications.

LoggrJack is not meant to replace a SIEM or any other advanced security control.

Copyright © 2020 Craig Jackson

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

"""

import argparse
from collections import Counter
import colorama
from datetime import datetime
import geoip2.database
import hashlib
import ipaddress
import ipwhois
import os
import re
import requests
import signal
import socket
import sys
import time

__author__ = "Craig Jackson"
__license__ = "Apache License 2.0"
__version__ = "1.3.0"

###############################################
###    Global Variables & Supporting Data   ###
###############################################

class globalRes():

    """
    The results counters (total, printed, and processed)
    """

    resTotal = 0 # Total events in loaded log file
    resProc = 0 # Events processed after log cleanup (-g parameter)
    resPrint = 0 # Events printed after user-defined filters / exclusions

class extInfLbl():

    """
    LoggrJack provides three slots in each eventDict value for extra information - that is, information
    relevant to each log type, but is not consistent beween log types. The labels for this extra
    information have to be provided for each log type. Variables are instanciated here, set in Main,
    and used by the resultsOut function.
    """

    extInfLbl1 = ""
    extInfLbl2 = ""
    extInfLbl3 = ""

class txtColor():

    """
    Colorized text to highlight certain kinds of output
    """

    colGood = "\033[32m" # Green
    colInfo = "\033[34m" # Blue
    colWarn = "\033[31m" # Red
    colErr = "\033[33m"  # Yellow
    colNorm = "\033[0m"  # Reset to default

# Set dict variables with relevant Microsoft 365 log info
# Details obtained from https://docs.microsoft.com/en-us/microsoft-365/compliance/detailed-properties-in-the-office-365-audit-log?view=o365-worldwide

logUserType = {
    "0" : "A regular user",
    "2" : "An administrator in your Microsoft 365 organization",
    "3" : "A Microsoft datacenter administrator or datacenter system account",
    "4" : "A system account",
    "5" : "An application",
    "6" : "A service principal",
    "7" : "A custom policy",
    "8" : "A system policy"
}

logLogonType = {
    "0" : "Indicates a mailbox owner",
    "1" : "Indicates an administrator",
    "2" : "Indicates a delegate",
    "3" : "Indicates the transport service in the Microsoft datacenter",
    "4" : "Indicates a service account in the Microsoft datacenter",
    "6" : "Indicates a delegated administrator",
}

logRecordType = {
    "1" : "Exchange Admin Audit Log event",
    "2" : "Exchange mailbox audit event (single mailbox)",
    "3" : "Exchange mailbox audit event (multiple mailboxes)",
    "8" : "Azure Active Directory admin operation",
    "15" : "Azure Active Directory Secure Token Service (STS) logon event (user logon)",
    "18" : "Security & Compliance Center event",
    "19" : "Aggregated, repetitive Exchange mailbox operations event",
    "23" : "Skype for Business event",
    "28" : "Exchange Online Protection phishing and malware event",
    "29" : "Exchange Online Protection submission event",
    "40" : "Security & Compliance Cener alert signal event",
    "41" : "Office365 safe links time-of-block or block override event",
    "50" : "MailItemsAccessed mailbox audit event",
    "51" : "Anti-spam and mail hygiene event",
    "62" : "Email attack campaign event",
    "64" : "Automated investigation and response event",
    "65" : "Quarantine audit record event",
}

###############################################
###            General Functions            ###
###############################################

def printBanner():

    """
    Function: Print a delightful banner
    Called from: main
    """

    theLogo = """
                  _                              _            _
                 | |    ___  __ _  __ _  _ _  _ | | __ _  __ | |__
                 | |__ / _ \/ _` |/ _` || '_|| || |/ _` |/ _|| / /
                 |____|\___/\__, |\__, ||_|   \__/ \__,_|\__||_\_\\
                            |___/ |___/
                                  Version: {}
    """.format(__version__)

    print(theLogo)

def printVer():

    """
    Function: Prints detailed version info
    Called from: main
    """

    print("                    LoggrJack - Log Parsing and Analysis tool")
    print("                                 Version " + __version__)
    print("                            Created by " + __author__ + "\r\n")

def argCheck(args):

    """
    Function: Checks the args passed by the user to confirm there aren't any conflicts
    Called from: main
    """

    ## If only the version is being printed, all other arg checks can be skipped

    if not args.printVer:

        ### Log file (-l) and geolocation database (-m) arguments are always required unless the detailed version is being printed

        if not args.LogFile and not args.DBFile:
            print ("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] You must pass the log file (-l) and geolocation database file (-m) with each analysis. Please try again.\r\n")
            sys.exit()

        ### A log type selection (-t) is always required and must be one of several defined numerical values between 1 and 4

        if not args.logType:
            print ("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] You must pass the log type (-t) with each analysis. Please try again.\r\n")
            sys.exit()
        else:
            if not 0 < int(args.logType) < 5:
                print ("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] You must pass specific numeric values (e.g., 1) for the log type (-t). Please review the help menu (-h) and try again.\r\n")
                sys.exit()

        ### IP dump (-i) and the log summary (-s) can't be passed simultaneously

        if (args.lIPs and args.topNum):
            print ("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] You cannot pass both the IP dump (-i) arguments and the summary function (-s) arguments simultaneously. Please select one and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) can't be passed simultaneously

        if (args.filterType and args.excludeType):
            print ("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] You cannot pass both filter (-d) and exclude (-x) arguments simultaneously. Please select one and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) require the data (-d) parameter

        if ((args.filterType or args.excludeType) and not args.modifierData):
            print("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Use of the filter (-f) and exclude (-x) arguments requires the Modifier Data (-d) argument. Please include the -d parameter and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) arguments can only be one of four values

        if args.filterType:
            filterTest = args.filterType.lower()
            if (filterTest != "user") and (filterTest != "ip") and (filterTest != "country") and (filterTest != "domain"):
                print("\r\n\[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] The filter (-f) argument can only be one of four values (i.e. 'user', 'ip', 'country', 'domain').\r\n")
                sys.exit()

        if args.excludeType:
            excludeTest = args.excludeType.lower()
            if (excludeTest != "user") and (excludeTest != "ip") and (excludeTest != "country") and (excludeTest != "domain"):
                print("\r\n\[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] The exclude (-x) argument can only be one of four values (i.e. 'user', 'ip', 'country', 'domain').\r\n")
                sys.exit()

        ### Have I Been Pwned lookups (-p) require the summary function (-s) parameter

        if args.hibpAPIKey and not args.topNum:
            print("\r\n[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Have I Been Pwned lookups (-p) can only be passed with the log summary function (-s). Please select both and try again.\r\n")
            sys.exit()

def catchSigs(signum, frame):

    """
    Function: Catch SIGINTs and other fun things
    Called from: main
    """

    ## Calculate the number of processed events vs the total calculated from the log

    remEvt = globalRes.resProc / globalRes.resTotal
    remPerc = str(f'{remEvt:.2%}')

    ## Print completion stats to screen and exit

    print("\r\n["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] Caught a Keyboard Interrupt. Exiting with " + str(f'{globalRes.resProc:,}') + " of " +
        str(f'{globalRes.resTotal:,}') + " (" + remPerc + ") events processed.")
    sys.exit()

def getFilterDict(args):

    """
    Function: An entire function just to notify the user of the arguments they've passed to the script? Seems reasonable.
    Called from: main
    """

    ## Set variables for organization; this can be probably be removed later

    outText = {}
    outAction = ""
    userString = ""
    ipString = ""
    ctryString = ""
    domainString = ""
    evntString = ""

    ## Split the modifierData variable if user passed multiple values in a comma-separated list

    if args.modifierData:
        modData = args.modifierData.split(",")

    ## Set analysis type as one of the three main functions available

    if args.lIPs:
        outAction = "Analysis Type: IP dump"
    elif args.topNum:
        outAction = "Analysis Type: Log summary"
    else:
        outAction = "Analysis Type: Detailed Analysis"

    ## Determine if results will be filtered or excluded by user & create output string. Note
    ## that usernames passed in DOMAIN\USERNAME format will need to be converted back to a
    ## single backslash (\) where the user escaped command input with a double backslash (\\)

    try:
        if args.filterType.lower() == "user" or args.excludeType.lower() == "user":
            for i in range(0,(len(modData))):
                if userString == "":
                    userString = modData[i].replace("\\\\","\\")
                else:
                    userString = userString + ", " + modData[i].replace("\\\\","\\")
            if args.filterType:
                userString = "   Users - Only " + userString
            else:
                userString = "   Users - All except " + userString
    except:
        pass

    ## Determine if results will be filtered or excluded by IP address & create output string

    try:
        if args.filterType.lower() == "ip" or args.excludeType.lower() == "ip":
            for i in range(0,(len(modData))):
                if ipString == "":
                    ipString = modData[i]
                else:
                    ipString = ipString + ", " + modData[i]
            if args.filterType:
                ipString = "   IPs - Only " + ipString
            else:
                ipString = "   IPs - All except " + ipString
    except:
        pass

    ## If the user passed the -P argument to omit private IP addresses, add it to IP line

    if args.privIP:
        if ipString == "":
            ipString = "   IPs - All except internal addresses"
        else:
            ipString += ", and internal addresses"

    ## Determine if results will be filtered or excluded by country & create output string

    try:
        if args.filterType.lower() == "country" or args.excludeType.lower() == "country":
            for i in range(0,(len(modData))):
                if ctryString == "":
                    ctryString = modData[i]
                else:
                    ctryString = ctryString + ", " + modData[i]
            if args.filterType:
                ctryString = "   Countries - Only " + ctryString
            else:
                ctryString = "   Countries - All except " + ctryString
    except:
        pass

    ## Determine if results will be filtered or excluded by domain & create output string

    try:
        if args.filterType.lower() == "domain" or args.excludeType.lower() == "domain":
            for i in range(0,(len(modData))):
                if domainString == "":
                    domainString = modData[i]
                else:
                    domainString = domainString + ", " + modData[i]
            if args.filterType:
                domainString = "   Domains - Only " + domainString
            else:
                domainString = "   Domains - All except " + domainString
    except:
        pass

    ## Determine if benign 'garbage' events will be filtered out and update misc event filter string

    if args.logGarbage:
        evntString = "No garbage events"

    ## Determine if only known cities will be presented in the results and update misc event filter string

    if args.kCity:
        if evntString == "":
            evntString = "No unknown cities"
        else:
            evntString = evntString + ", no unknown cities"

    ## Determine if events will only be filtered to IPs with foreign geolocation and update filter string

    if args.warnIP:
        if ipString == "":
            ipString = "   IPs - Only IPs foreign to current location"
        else:
            ipString = ipString + ", only IPs foreign to current location"

    ## If any filter strings are empty, replace them with notice that all events of the given type will be included in output

    if userString == "":
        userString = "   Users - ALL"
    if ipString == "":
        ipString = "   IPs - ALL"
    if ctryString == "":
        ctryString = "   Countries - ALL"
    if domainString == "":
        domainString = "   Domains - ALL"
    if evntString == "":
        evntString = "   Events - ALL"
    else:
        evntString = "   Events - " + evntString

    ## Arrange the outText dictionary to be passed back to main and ship it

    outText["outAction"] = outAction
    outText["userString"] = userString
    outText["ipString"] = ipString
    outText["ctryString"] = ctryString
    outText["domainString"] = domainString
    outText["evntString"] = evntString

    return outText

def parseDates(eventDict):

    """
    Function: Extracts the earliest and latest events from the log via eventDict and makes them readable
    Called from: main
    """

    ## Get the earliest and latest dates using the min and max functions, then format using DateTime. If the
    ## time

    earlyDate = min(sorted(eventDict.keys()))
    cleanEarlyDate = datetime.strftime(earlyDate,'%m/%d/%Y, %H:%M:%S')
    lateDate = max(sorted(eventDict.keys()))
    cleanLateDate = datetime.strftime(lateDate,'%m/%d/%Y, %H:%M:%S')

    return cleanEarlyDate, cleanLateDate

def privIPCheck(lineIP):

    """
    Function: Checks for internal / private addresses using (admittedly bad) regex
    Called from: geoLook, parseO365Auth, parseIIS
    """

    ## GeoIP doesn't always handle shortened IPv6 addresses correctly, so they need to be expanded

    if ":" in lineIP:

        ### IPv6 addresses with an appended IPv6 scope (e.g., %4) also cause trouble

        if "%" in lineIP:
            lineIP = ipaddress.ip_address(lineIP.split("%")[0]).exploded
        else:
            lineIP = ipaddress.ip_address(lineIP).exploded

    if ((re.match(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'172\.(?:1[6-9]|2[0-9]|3[0-2])\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'192\.168\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'127\.\d{1,3}\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'169\.254\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'^fe80\:.*',lineIP)) or
        (re.match(r'.*\:0001$',lineIP))):
        return True
    else:
        return False

def geoLook(lineIP,cityList):

    """
    Function: Provides the city and country location for a given IP address
    Called from: whereAmI, createSummary, dumpIPs, detailedAnalysis
    """

    eventGeo = []

    ## Check for internal / private address

    if privIPCheck(lineIP):
        eventGeo = ["ERROR","ERROR","Internal / Private Address"]
    else:

        ### Get the geolocation of the address and build the return variable

        try:
            geoInfo = cityList.city(lineIP)

            #### City data

            if geoInfo.city.name == "None" or len(geoInfo.city.names) == 0:
                eventGeo = ["Unknown City"]
            else:
                eventGeo = [geoInfo.city.name]

            #### Region data (state data in the US)

            if str(geoInfo.subdivisions.most_specific.name) == "" or str(geoInfo.subdivisions.most_specific.name) == "None":
                eventGeo.append("Unknown Region")
            else:
                eventGeo.append(str(geoInfo.subdivisions.most_specific.name))

            #### Country data

            if geoInfo.country.name == "" or geoInfo.country.name == "None":
                eventGeo.append("Unknown Country")
            else:
                eventGeo.append(geoInfo.country.name)

        except:

            #### If geolocation fails, it's still easier to pass a list back to avoid index errors in other functions

            eventGeo = ["ERROR","ERROR","UNKNOWN - GEOLOCATION ERROR"]

    return eventGeo

def whereAmI(cityList,ipSite):

    """
    Function: Attempts to identify the user's current country so it can be used for reference
    Called from: main
    """

    try:

        ### Try to get public IP, then use it to call the geoLook function
        ### If successful, get the current country name and pass it back

        currIPcall = requests.get('https://' + ipSite)
        currIP = currIPcall.text.strip("\n")
        currCountry = geoLook(currIP,cityList)[2]

    except:

        ### Attempt to get public IP failed, set currCountry variable accordingly

        currCountry = "Unknown"

    return currCountry

def getWhois(searchIP):

    """
    Function: Gets whois information for an IP so it can be shown when higher verbosity is desired
    Called from: resultsOut
    """

    ## Wait for 1 second so as not to be a burden or stack up WHOIS queries

    time.sleep(1)

    try:

        ### Attempt to connect to the relevant registrar and collect WHOIS record data

        prepIP = ipwhois.IPWhois(searchIP)
        record = ipwhois.IPWhois.lookup_rdap(prepIP)

        ### Parse the WHOIS record data and format relevant data as a list for return

        wiASN = record['asn']
        wiRegistrar = record['asn_registry']
        wiDesc = record['asn_description']
        wiName = record['network']['name']

        wiResults = [wiASN,wiRegistrar,wiDesc,wiName]

    except:

        ### WHOIS lookup failed; set return variable accordingly

        wiResults = "WHOIS lookup failed."

    return wiResults

def getHIBP(uName,hibpKey,verbLvl):

    """
    Function: Queries the Have I Been Pwned API to determine if info related to the username has been exposed in a breach
    Called from: createSummary
    """

    ## NOTE: If you modify this function in any way, it is your responsibility to ensure that your changes remain
    ## in compliance with the Have I Been Pwned API Acceptable Use guidelines (https://haveibeenpwned.com/api/v3)

    ## Wait for 1.5 seconds so as not to burden the HIBP API

    time.sleep(float(1.5))

    ## Create necessary request strings

    baseReqStr = "https://haveibeenpwned.com/api/v3/breachedaccount/" + uName
    headerDict = {'hibp-api-key':hibpKey,'user-agent':'LoggrJack ' + __version__ + ' (Linux / Mac / Win)'}

    ## Query HIBP and parse based on HTTP response code

    try:
        breachResp = requests.get(baseReqStr,headers=headerDict)

        if breachResp.status_code == 200:
            breachData = breachResp.json()
        elif breachResp.status_code == 401:
            breachData = "[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] The HIBP API key provided was not valid."
        elif breachResp.status_code == 404:
            if verbLvl > 0:
                breachData = "[OK] No breaches associated with this account."
            else:
                breachData = "[OK]"
        elif breachResp.status_code == 429:
            breachData = "[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] The HIBP rate limit has been exceeded."
        elif breachResp.status_code == 503:
            breachData = "[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] The HIBP service is unavailable."

    except:
        breachData = "[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Unable to query HIBP database. Check your Internet connection."

    return breachData

def createIPLists(eventDict):

    """
    Function: Creates raw lists of IPv4 and IPv6 addresses from log file for use by other functions
    Called from: createSummary, dumpIPs
    """

    allIPv4s = []
    allIPv6s = []

    ## Loop through eventDict and add addresses to IPv4 or IPv6 lists

    for eachKey in eventDict.keys():

        ### Check to see if the value is a list of lists (i.e., more
        ### than one event took place at that time). If there are
        ### multiple items for a given time, then each of those items
        ### will need to be iterated.

        if isinstance(eventDict[eachKey][0],list):
            for i in range(0,len(eventDict[eachKey])):
                if "." in eventDict[eachKey][i][1]:
                    allIPv4s.append(eventDict[eachKey][i][1])
                else:
                    allIPv6s.append(eventDict[eachKey][i][1])
        else:
            if "." in eventDict[eachKey][1]:
                allIPv4s.append(eventDict[eachKey][1])
            else:
                allIPv6s.append(eventDict[eachKey][1])

    return allIPv4s, allIPv6s

###############################################
###       Analysis / Output Functions       ###
###############################################

def createSummary(eventDict,topNum,cityList,currLoc,verbLvl,hibpKey):

    """
    Function: Summarizes the data in the log file by top IPs and all users (per the -s parameter)
    Called from: main
    """

    ## Part 1 dumps the top IP addresses (10 by default) by number of accesses
    ## Start by getting raw lists of IPv4 and IPv6 addresses from eventDict

    allIPv4s, allIPv6s = createIPLists(eventDict)

    ## Created sorted Counter dictionary in decsending (most to least hits) order

    sortedIPv4s = sorted(((value,key) for (key,value) in Counter(allIPv4s).items()),reverse=True)
    sortedIPv6s = sorted(((value,key) for (key,value) in Counter(allIPv6s).items()),reverse=True)

    ## Print output. If the user entered a 'top n' number that's greater than the length of the list,
    ## lower it (topNum variable) to the length of the list to dodge index errors

    print ("["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] The top " + str(topNum) + " most frequent IPv4 source addresses are:")

    if topNum > len(sortedIPv4s):
        topNum = len(sortedIPv4s)

    if len(sortedIPv4s) == 0:
        print("No source IP addresses met this criteria.")
    else:
        for i in range(0,topNum):
            print (sortedIPv4s[i][1] + " - " + str(f'{sortedIPv4s[i][0]:,}') + " hit(s)")

    print ("\r\n["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] The top " + str(topNum) + " most frequent IPv6 source addresses are:")

    if topNum > len(sortedIPv6s):
        topNum = len(sortedIPv6s)

    if len(sortedIPv6s) == 0:
        print("No source IP addresses met this criteria.")
    else:
        for i in range(0,topNum):
            print (sortedIPv6s[i][1] + " - " + str(f'{sortedIPv6s[i][0]:,}') + " hit(s)")

    ## Part 2 checks through all IPs and provides notification when an IP doesn't align with the current country
    ## foundOne is used to notify the user if no results are found from this section

    foundOne = False

    print ("\r\n["+ txtColor.colErr + "WARN" + txtColor.colNorm + "] The following source IP addresses did NOT geolocate to your current country:")

    ## Cycle through each line data item, pull the geolocation, and see if it matches the user's current location

    for i in range(0,len(sortedIPv4s)):
        ipGeo = geoLook(sortedIPv4s[i][1],cityList)
        if ipGeo[0] == "ERROR":
            continue
        else:
            if ipGeo[2] != currLoc and not "Internal" in ipGeo[2]:
                print(sortedIPv4s[i][1] + " (" + ipGeo[0] + ", " + ipGeo[1] + ", " + txtColor.colWarn + ipGeo[2] + txtColor.colNorm + ") - " + str(sortedIPv4s[i][0]) + " hit(s)")
                foundOne = True

    for i in range(0,len(sortedIPv6s)):
        ipGeo = geoLook(sortedIPv6s[i][1],cityList)
        if ipGeo[0] == "ERROR":
            continue
        else:
            if ipGeo[2] != currLoc and not "Internal" in ipGeo[2]:
                print(sortedIPv6s[i][1] + " (" + ipGeo[0] + ", " + ipGeo[1] + ", " + txtColor.colWarn + ipGeo[2] + txtColor.colNorm + ") - " + str(sortedIPv6s[i][0]) + " hit(s)")
                foundOne = True

    ## If everything geolocated to the user's current location, let them know

    if foundOne == False:
        print("No source IP addresses met this criteria.")

    ## Part 3 aggregates data for each user and provides a summary of their authentictions and locations
    ## If a Have I Been Pwned lookup has been requested, make preparations

    if hibpKey != "None":

        ### Compile regex to validate email addresses
        ### Absurd regex taken from https://stackoverflow.com/questions/201323/how-to-validate-an-email-address-using-a-regular-expression

        emailCheck = re.compile(r"(?:[a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*|" \
            "'(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*')" \
            "@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]" \
            "|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|" \
            "[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])")

        ### If the user set verbosity at 2 or higher, pull down the full breach list so data classes can be referenced

        if verbLvl > 1:
            baseReqStr = "https://haveibeenpwned.com/api/v3/breaches/"
            headerDict = {'hibp-api-key':hibpKey,'user-agent':'LoggrJack ' + __version__ + ', Linux / Mac / Win)'}
            allBreaches = requests.get(baseReqStr,headers=headerDict)
            allBreaches = allBreaches.json()

    ## Proceed with the rest of part 3

    print("\r\n["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] Summarizing all user activity from this log:")

    userDict = {}

    ## Build the user dictionary with users as key and a list of IPs as the value
    ## Each key / value pair needs to be tested for a list of lists in the value field
    ## in instances where multiple events take at the same time.

    for thisKey in eventDict.keys():
        if isinstance(eventDict[thisKey][0],list):
            for eachVal in range(0,len(eventDict[thisKey])):
                eventUser = eventDict[thisKey][eachVal][0]
                eventIP = eventDict[thisKey][eachVal][1]

                if not eventUser in userDict.keys():
                    userDict[eventUser] = [eventIP]
                else:
                    if not isinstance(userDict[eventUser],list):
                        ##### Convert value of existing dictionary entry to a list to accomodate multiple entries
                        userDict[eventUser] = [userDict[eventUser]]
                    userDict[eventUser].append(eventIP)
        else:
            eventUser = eventDict[thisKey][0]
            eventIP = eventDict[thisKey][1]

            if not eventUser in userDict.keys():
                userDict[eventUser] = [eventIP]
            else:
                if not isinstance(userDict[eventUser],list):
                    ##### Convert value of existing dictionary entry to a list to accomodate multiple entries
                    userDict[eventUser] = [userDict[eventUser]]
                userDict[eventUser].append(eventIP)

        ### Iterate the processed event counter

        globalRes.resProc += 1

    ## With the dictionary built, start building individual user lists that can be printed to screen

    for thisKey in userDict.keys():
        geoList = []
        userName = thisKey
        ipList = userDict[thisKey]

        ### Loop through IPs and get geolocation data for each in case the user has
        ### auth'ed from muliple countries

        if len(ipList) < 2:
            thisCountry = geoLook(indIP, cityList)[2]
            geoList.append(thisCountry)
        else:
            for indIP in ipList:
                thisCountry = geoLook(indIP, cityList)[2]
                geoList.append(thisCountry)

        ### Convert to set and back to eliminate redundant countries

        geoList = list(set(geoList))

        ### Build the base output string by iterating through geoList

        if geoList[0] != currLoc and not "Internal" in geoList[0]:
            reportStr = "User " + userName + " - " + str(f'{len(ipList):,}') + " authentication(s) from " + txtColor.colWarn + geoList[0] + txtColor.colNorm
        else:
            reportStr = "User " + userName + " - " + str(f'{len(ipList):,}') + " authentication(s) from " + geoList[0]

        ### If necessary, add additional source countries, then print the output

        for i in range(1,len(geoList)):
            if geoList[i] != currLoc and not "Internal" in geoList[i]:
                reportStr += ", " + txtColor.colWarn + geoList[i] + txtColor.colNorm
            else:
                reportStr += ", " + geoList[i]

        print (reportStr)

        ### If the user has provided an API key for HaveIBeenPwned, submit and parse the request, then print the result

        if hibpKey != "None":

            #### Have I Been Pwned only allows searches of email addresses
            #### Check for validity of username, which is stored in thisKey variable

            #### Some usernames may have other text added that needs to be removed depending on the verbosity level

            if "(" in thisKey:
                thisKey = thisKey.split("(")[0].strip()

            if not re.fullmatch(emailCheck,thisKey.lower()):
                print("    *HIBP Status: [" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Username doesn't appear to be a valid email address.")
            else:

                userBreach = getHIBP(thisKey,hibpKey,verbLvl)

                if ("[OK]" in userBreach) or ("[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "]" in userBreach):
                    print("    *HIBP Status: " + userBreach)
                else:
                    if verbLvl == 0:
                        print("    *HIBP Status: [" + txtColor.colWarn + "PWNED" + txtColor.colNorm + "]")
                    if verbLvl == 1:
                        print("    *HIBP Status: [" + txtColor.colWarn + "PWNED" + txtColor.colNorm + "] User account found in " + str(len(userBreach)) + " breaches.")
                    elif verbLvl > 1:
                        print("    *HIBP Status: [" + txtColor.colWarn + "PWNED" + txtColor.colNorm + "] User account found in the following " + str(len(userBreach)) + " breaches:")

                        ####### Create necessary request strings

                        for i in range(0, len(userBreach)):

                            breachStr = []
                            breachName = userBreach[i]['Name']

                            ######## Get the index of this breach from the allBreaches list, then convert to Int

                            breachIdx = [i for i, e in enumerate(allBreaches) if e['Name'] == breachName]
                            breachIdx = int(breachIdx[0])

                            ######## Iterate through the DataClasses list from this breach
                            ######## and add all items in the list to the breachStr

                            ######## Passwords, usernames, and email addresses should always
                            ######## be included as critical data types

                            if "Passwords" in allBreaches[breachIdx]['DataClasses']:
                                breachStr = "Passwords"

                            if "Email addresses" in allBreaches[breachIdx]['DataClasses']:
                                if len(breachStr) == 0:
                                    breachStr = "Email addresses"
                                else:
                                    breachStr = breachStr + ", email addresses"

                            if "Usernames" in allBreaches[breachIdx]['DataClasses']:
                                if len(breachStr) == 0:
                                    breachStr = "Usernames"
                                else:
                                    breachStr = breachStr + ", usernames"

                            ######## Limit the number of data types listed for each breach, because
                            ######## some of the breach dumps (e.g. Exactis) have dozens and it gets unwieldy

                            if len(allBreaches[breachIdx]['DataClasses']) > 10:
                                upperLimit = 10
                            else:
                                upperLimit = len(allBreaches[breachIdx]['DataClasses'])

                            ######## Add other data types to the data type string as long as they aren't
                            ######## already there from the critical items above

                            for dType in range(0, (upperLimit - len(breachStr.split(",")))):
                                if (len(breachStr) == 0):
                                    breachStr = allBreaches[breachIdx]['DataClasses'][dType].capitalize()
                                elif not (allBreaches[breachIdx]['DataClasses'][dType].lower() in breachStr.lower()):
                                    breachStr = breachStr + ", " + allBreaches[breachIdx]['DataClasses'][dType].lower()

                            ######## Add the breach name to the front and print the final output string

                            breachStr = breachName + " - " + breachStr
                            print("        -" + breachStr)

def dumpIPs(eventDict,verbLvl,cityList,currLoc,noPrivs):

    """
    Function: Dumps only a sorted list of unique IPs (per the -i parameter)
    Called from: main
    """

    allIPs = []

    ## Get raw lists of IPv4 and IPv6 addresses from eventDict

    allIPv4s, allIPv6s = createIPLists(eventDict)

    ## Create ordered list of unique IP addresses in ascending order

    sortedIPv4s = sorted(list(set(allIPv4s)),key=ipaddress.IPv4Address)
    sortedIPv6s = sorted(list(set(allIPv6s)),key=ipaddress.IPv6Address)

    ## Combined the ordered IP address lists into one master list

    for i in range(0,len(sortedIPv4s)):
        allIPs.append(sortedIPv4s[i])

    for i in range(0,len(sortedIPv6s)):
        allIPs.append(sortedIPv6s[i])

    ## Print each IP to screen, including geolocation info if higher verbosity is set

    for i in range(0,len(allIPs)):
        lineGeo = geoLook(allIPs[i],cityList)

        if verbLvl > 0:

            if verbLvl == 1:
                if lineGeo[2] != currLoc and not "Internal" in lineGeo[2]:
                    print(allIPs[i] + " (" + txtColor.colWarn + lineGeo[2] + txtColor.colNorm + ")")
                else:
                    print(allIPs[i] + " (" + lineGeo[2] + ")")

            if verbLvl > 1:
                if lineGeo[1] == "ERROR":
                    print(allIPs[i] + " (" + lineGeo[2] + ")")
                else:
                    if lineGeo[2] != currLoc and not "Internal" in lineGeo[2]:
                        print(allIPs[i] + " (" + lineGeo[0] + ", " + lineGeo[1] + ", " + txtColor.colWarn + lineGeo[2] + txtColor.colNorm + ")")
                    else:
                        print(allIPs[i] + " (" + lineGeo[0] + ", " + lineGeo[1] + ", " + lineGeo[2] + ")")

        else:
            print(allIPs[i])

    return [len(sortedIPv4s),len(sortedIPv6s)]

def detailedAnalysis(eventDict,cityList,args,currLoc,verbLvl):

    """
    Function: Parses the event log line by line and provides an ordered, filtered output with geolocation info added
    Called from: main
    """

    ## Sort event dictionary by earliest to latest event, then extract relevant data

    for thisKey in sorted(eventDict.keys()):
        if isinstance(eventDict[thisKey][0],list):
            for eachVal in range(0,len(eventDict[thisKey])):
                eventDate = datetime.strftime(thisKey, '%m/%d/%Y')
                eventTime = datetime.strftime(thisKey, '%H:%M:%S')
                eventUser = eventDict[thisKey][eachVal][0]
                eventIP = eventDict[thisKey][eachVal][1]
                eventExt1 = eventDict[thisKey][eachVal][2]
                eventExt2 = eventDict[thisKey][eachVal][3]
                eventExt3 = eventDict[thisKey][eachVal][4]
                eventGeo = geoLook(eventIP, cityList)
                eventInfo = [eventDate,eventTime,eventUser,eventGeo[0],eventGeo[1],eventGeo[2],eventIP,eventExt1,eventExt2,eventExt3]

                resultsOut(eventInfo,args,currLoc,verbLvl)

        else:
            eventDate = datetime.strftime(thisKey, '%m/%d/%Y')
            eventTime = datetime.strftime(thisKey, '%H:%M:%S')
            eventUser = eventDict[thisKey][0]
            eventIP = eventDict[thisKey][1]
            eventExt1 = eventDict[thisKey][2]
            eventExt2 = eventDict[thisKey][3]
            eventExt3 = eventDict[thisKey][4]
            eventGeo = geoLook(eventIP, cityList)
            eventInfo = [eventDate,eventTime,eventUser,eventGeo[0],eventGeo[1],eventGeo[2],eventIP,eventExt1,eventExt2,eventExt3]

            resultsOut(eventInfo,args,currLoc,verbLvl)

def resultsOut(eventInfo,args,currLoc,verbLvl):

    """
    Function: Formats and prints per-line output based upon the selections passed by the user
    Called from: detailedAnalysis
    """

    ## Iterate the processed event counter and set eventMatch to False
    ## eventMatch dictates whether the event is printed after all filters and criteria have been checked

    globalRes.resProc += 1
    eventMatch = False

    ## Filter out events with Unknown Cities (-k) if set by user

    if args.kCity and eventInfo[3] == "Unknown City":
        return

    ## Filter out events that goeolocate to current country (-w) if set by user

    if args.warnIP and eventInfo[5] == currLoc:
        return

    ## Filter out events containing certain info (-f) as passed by the user

    if args.filterType:
        if args.filterType.lower() == "user":
            for itemCheck in args.modifierData.split(","):
                if re.match(itemCheck, eventInfo[2],re.IGNORECASE):   # Had to change to match from fullmatch because
                    eventMatch = True                                 # of O365 UserIDs in some events
                    break
        elif args.filterType.lower() == "ip":
            for itemCheck in args.modifierData.split(","):
                if re.fullmatch(itemCheck, eventInfo[6],re.IGNORECASE):
                    eventMatch = True
                    break
        elif args.filterType.lower() == "country":
            for itemCheck in args.modifierData.split(","):
                if re.fullmatch(itemCheck, eventInfo[5],re.IGNORECASE):
                    eventMatch = True
                    break
        elif args.filterType.lower() == "domain":
            for itemCheck in args.modifierData.split(","):
                if "@" in eventInfo[2]:
                    if re.fullmatch(itemCheck, eventInfo[2].split("@")[1],re.IGNORECASE):
                        eventMatch = True
                        break

    ## Exclude certain events containing info (-x) passed by the user

    elif args.excludeType:
        if args.excludeType.lower() == "user":
            for itemCheck in args.modifierData.split(","):
                if not re.match(itemCheck, eventInfo[2],re.IGNORECASE):  # Had to change to match from fullmatch because
                    eventMatch = True                                    # of O365 UserIDs in some events
                    break
        elif args.excludeType.lower() == "ip":
            for itemCheck in args.modifierData.split(","):
                if not re.fullmatch(itemCheck, eventInfo[6],re.IGNORECASE):
                    eventMatch = True
                    break
        elif args.excludeType.lower() == "country":
            for itemCheck in args.modifierData.split(","):
                if not re.fullmatch(itemCheck, eventInfo[5],re.IGNORECASE):
                    eventMatch = True
                    break
        elif args.excludeType.lower() == "domain":
            for itemCheck in args.modifierData.split(","):
                if "@" in eventInfo[2]:
                    if not re.fullmatch(itemCheck, eventInfo[2].split("@")[1],re.IGNORECASE):
                        eventMatch = True
                        break

    ## Otherwise, the event automatically matches

    else:
        eventMatch = True

    ## If the event matches, print the output based on the verbosity level set by the user (-v)
    ## If it doesn't match, go back for the next event line

    if eventMatch == True:
        globalRes.resPrint += 1

        ### If user passed higher verbosity levels, additional info levels need to be printed

        if verbLvl > 0:

            #### Level one adds city and region informaion to geolocation

            if "Internal" in eventInfo[5]:
                print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[5] + ")")
            else:
                if eventInfo[5] != currLoc:
                    print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[3] + ", " + eventInfo[4] + ", " +
                        txtColor.colWarn + eventInfo[5] + txtColor.colNorm + ")")
                else:
                    print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[3] + ", " + eventInfo[4] + ", " + eventInfo[5] + ")")


            #### Level two adds the extra information pulled for each log type

            if verbLvl > 1:
                print("    " + extInfLbl.extInfLbl1 + ": " + eventInfo[7])
                print("    " + extInfLbl.extInfLbl2 + ": " + eventInfo[8])
                print("    " + extInfLbl.extInfLbl3 + ": " + eventInfo[9])

            #### Level three adds WHOIS information for the IP address

            if verbLvl > 2:
                wiInfo = getWhois(eventInfo[6])
                if wiInfo == "WHOIS lookup failed.":
                    print("    [" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] " + wiInfo)
                else:
                    print("    IP ASN: " + wiInfo[0])
                    print("    IP Registrar: " + wiInfo[1])
                    print("    IP ASN Description: " + wiInfo[2])
                    print("    IP Org Name: " + wiInfo[3])
        else:

            ##### No extra verbosity, print the basic information

            if eventInfo[5] != currLoc and not "Internal" in eventInfo[5]:
                print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + txtColor.colWarn + eventInfo[5] + txtColor.colNorm + ")")
            else:
                print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[5] + ")")
    else:
        return

###############################################
###           Log Parser Functions          ###
###############################################

# NOTE! eventDict key / value pairs need to follow the same order when parsing all logs
# The order should always be:
#
# Key: Event timestamp (combined as a datetime object)
# Value: Username, Source IP address, exra info 1, extra info 2, extra info 3

def parseO365Auth(fileText, verbLvl, noPrivs, noGarbage):

    """
    Function: Parses an O365 event log for use with LoggrJack's core function
    Called from: Main
    """

    ## Count the total number of events in the file and update the global variable
    ## O365 auth logs tend to have one garbage header line that needs to be skipped

    globalRes.resTotal = len(fileText) - 1

    ## Begin reading through each line of the file and extracting the necessary data

    eventDict = {}

    for i in range(1,len(fileText)):

        ### If the user has elected to omit garbage events (-g), events containing
        ### 'FaultDomainRedirect' are benign redirects that don't provide much value
        ### and clutter logs. Events with a 'Sync_Service' username can also be omitted.

        if noGarbage:
            if "FaultDomainRedirect" in fileText[i] or "Sync_Service" in fileText[i]:
                continue

        ### Split text by most common delimiter, in this case a comma

        splitTxt = fileText[i].split(",")

        ### Set relevant event variables by splitting relevant log text

        lineDateTime = datetime.strptime(splitTxt[0],"%Y-%m-%dT%H:%M:%S.%f0Z")
        lineIP = splitTxt[13].split("\"")[6]
        extInf1 = fileText[i].split("{")[1].split(",")[7].split(":")[1] # User Type
        extInf2 = fileText[i].split("{")[1].split(",")[4].split(":")[1] # Record Type
        extInf3 = re.findall(r'\"\"Actor\"\"\:\[\{\"\"ID\"\"\:\"\"(.*?)\"\"\,\"',fileText[i])[0] # User GUID

        ### Filter out this line item if the source IP is an internal /
        ### private address and the user has set the -P parameter

        if privIPCheck(lineIP) and noPrivs:
            continue

        ### Microsoft 365 sometimes uses a GUID-style string in the UserID column instead of
        ### an email address. This can be confusing during analysis. This section attempts to locate the
        ### email address from a separate part of the logged event if the GUID is found the normal UserID column

        if not "@" in splitTxt[1] and "@" in fileText[i].split("{")[1].split(",")[6].split(":")[1].replace("\"",""):
            if verbLvl != 0:
                lineUser = fileText[i].split("{")[1].split(",")[6].split(":")[1].replace("\"","") + " (converted from user GUID)"
            else:
                lineUser = fileText[i].split("{")[1].split(",")[6].split(":")[1].replace("\"","")
        else:
            lineUser = splitTxt[1]

        ### Add some extra detail to the UserType and RecordType output based
        ### on the Microsoft 365 event dicts included above

        extInf1 += " - " + logUserType[extInf1]
        extInf2 += " - " + logRecordType[extInf2]

        ### Add this event to the master event dictionary

        if not lineDateTime in eventDict.keys():
            eventDict[lineDateTime] = [lineUser,lineIP,extInf1,extInf2,extInf3]
        else:
            if not isinstance(eventDict[lineDateTime][0],list):
                ##### Convert value to a list to accomodate multiple values per key
                eventDict[lineDateTime] = [eventDict[lineDateTime]]
            eventDict[lineDateTime].append([lineUser,lineIP,extInf1,extInf2,extInf3])

    return eventDict

def parseIIS(fileText, verbLvl, noPrivs, noGarbage, emlDomain):

    """
    Function: Parses an IIS log in W3C format for use with LoggrJack's core function
    Called from: Main
    """

    ## Count the total number of events in the file and update the global variable
    ## IIS logs tend to have four garbage header lines that need to be skipped

    globalRes.resTotal = len(fileText) - 4

    ## Begin reading through each line of the file and extracting the necessary data

    eventDict = {}

    for i in range(4,len(fileText)):

        ### IIS logs sometimes contain headers in the middle of the file. Those lines
        ### begin with a # and can be skipped.

        if not fileText[i][0] == "#":

            ### Split text by most common delimiter, in this case a space

            splitTxt = fileText[i].split(" ")

            ### If the user has elected to omit garbage events (-g), events containing
            ### 'HealthMailbox' are internal maintenance and can be omitted. Also, some
            ### events with an empty username (marked "-" by IIS) may be skipped because
            ### they don't provide much value and clutter logs.

            if noGarbage:
                if "HealthMailbox" in fileText[i] or splitTxt[7] == "-":
                    continue

            ### Set relevant event variables by splitting log text

            lineUser = "" # Hold for later
            lineDateTime = datetime.strptime(splitTxt[0] + " " + splitTxt[1],"%Y-%m-%d %H:%M:%S")
            lineIP = splitTxt[8]
            extInf1 = splitTxt[4] # URI stem
            extInf2 = splitTxt[9] # User-Agent string
            extInf3 = splitTxt[3] + " (" + splitTxt[11] + " response)" # Method and server response

            ### Filter out this line item if the source IP is an internal /
            ### private address and the user has set the -P parameter

            if privIPCheck(lineIP) and noPrivs:
                continue

            ### IIS logs list usernames in DOMAIN\USERNAME format, which can't be used for data
            ### enrichment functions like HIBP calls. If the user passes the Domain option (-D)
            ### LoggrJack will attempt to append that domain to identified user accounts to
            ### create an email address. If this can't be accomplished, LoggrJack falls back to
            ### the DOMAIN\USERNAME format.

            if emlDomain:

                if emlDomain == "getDefault":

                    emlDomain = re.findall(r'\@(.*?)[\&\:]',splitTxt[5]) # Attempt to extract domain from event metadata

                    if len(emlDomain) > 0:
                        emlDomain = emlDomain[0]

                if len(emlDomain) > 0:

                    #### Differentiate between usernames that have the NetBIOS domain included versus
                    #### those that do not, and add the email domain as appropriate.

                    if "\\" in splitTxt[7]:
                        lineUser = splitTxt[7].split("\\")[1] + "@" + emlDomain
                    elif "/" in splitTxt[7]:
                        lineUser = splitTxt[7].split("/")[1] + "@" + emlDomain
                    else:
                        lineUser = splitTxt[7] + "@" + emlDomain

            ### Set username to default if an email address format couldn't be created

            if len(lineUser) == 0:
                lineUser = splitTxt[7]

            ### Add this event to the master event dictionary

            if not lineDateTime in eventDict.keys():
                eventDict[lineDateTime] = [lineUser,lineIP,extInf1,extInf2,extInf3]
            else:
                if not isinstance(eventDict[lineDateTime][0],list):
                    ##### Convert value to a list to accomodate multiple values per key
                    eventDict[lineDateTime] = [eventDict[lineDateTime]]
                eventDict[lineDateTime].append([lineUser,lineIP,extInf1,extInf2,extInf3])

    return eventDict

###############################################
###              Main Function              ###
###############################################

def main():

    """
    Function: Get after it
    Called from: N/A
    """

    ## Print the banner, including current version

    printBanner()

    ## Set the SIGINT handler to catch keyboard interrupts

    signal.signal(signal.SIGINT, catchSigs)

    ## Initialize Colorama early so errors thrown on Windows prior to
    ## arg parsing won't contain ANSI codes

    try:
        colorama.init()
    except:
        print("[ERROR] Failed to initialize Colorama. Exiting.")
        sys.exit()

    ## Create args and arg parser

    parser = argparse.ArgumentParser(
        usage='python %s -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] [OPTIONS]' % sys.argv[0],
        add_help=False,
        description='LoggrJack - Simplify Text-Based Log Analysis',
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog,max_help_position=45))

    reqArgs = parser.add_argument_group('Required Arguments')
    funArgs = parser.add_argument_group('Function Arguments')
    optArgs = parser.add_argument_group('Optional Arguments')

    reqArgs.add_argument('-l','--log',required=False,help='Sets the path to the log file to be analyzed',dest='LogFile')
    reqArgs.add_argument('-m','--mmdb',required=False,help='Sets the path to the MaxMind GeoIP2 database in mmdb format',dest='DBFile')
    reqArgs.add_argument('-t','--type',required=False,help='Designates the log type being submitted for analysis:\r\n \
        *1 - Microsoft 365 Auth (User Logged In)\r\n \
        *2 - Microsoft 365 General - COMING SOON \r\n \
        *3 - Azure Active Directory - COMING SOON\r\n \
        *4 - Microsoft IIS (All events in W3C format)\r\n \
        *5 - Debian Auth.log - COMING SOON',dest='logType')

    funArgs.add_argument('-s','--summary',required=False,help='Provides a summary of the data found in the log file provided with the top n number of hits (default: 10)',type=int,dest='topNum',nargs='?',const=10)
    funArgs.add_argument('-i','--ips',required=False,help='Dumps a list of all unique IP addresses found in the log file',dest='lIPs',action='store_true')

    optArgs.add_argument('-h','--help',help='Shows the command help',action='help')
    optArgs.add_argument('-V','--version',required=False,help='Prints version information',dest='printVer',action='store_true')
    optArgs.add_argument('-c','--color',required=False,help='Disables coloration of text output',dest='noColor',action='store_true')
    optArgs.add_argument('-e','--email',required=False,help='Designates an email domain that LoggrJack can use to create email addresses from NetBIOS-formatted usernames',dest='eDomain',nargs='?',type=str,const='getDefault')
    optArgs.add_argument('-M','--myip',required=False,help='Sets site used to check public IP for determining current location (default: icanhazip.com)',dest='myIP',default='icanhazip.com')
    optArgs.add_argument('-v','--verbose',required=False,help='Increases the verbosity of all output (e.g., printing city and region in addition to country)',default=0,dest='verbOut',action='count')
    optArgs.add_argument('-k','--knowncity',required=False,help='Suppresses results that do not geolocate to a known city',dest='kCity',action='store_true')
    optArgs.add_argument('-w','--warning',required=False,help='Filters results to only show connections originating from outside the current country',dest='warnIP',nargs='?',type=str,const='getDefault')
    optArgs.add_argument('-g','--garbage',required=False,help='Removes events that are benign and clutter logs (e.g. auth redirects)',dest='logGarbage',action='store_true')
    optArgs.add_argument('-P','--private',required=False,help='Removes internal or private (RFC 1918) IP addresses from output and shows only public addresses',dest='privIP',action='store_true')
    optArgs.add_argument('-p','--pwned',required=False,help='Queries the HaveIBeenPwned API to determine if logged email addresses have been compromised in a breach (Requires API key)',dest='hibpAPIKey')
    optArgs.add_argument('-f','--filter',required=False,help='Tells LoggrJack to filter results by a given value from the options shown below (requires the -d parameter):\r\n \
        *user - Filter results to only show a specific user or users ("e.g. andytaylor@example.com")\r\n \
        *ip - Filter results to only show a specfic IP address or addresses (e.g. "1.2.3.4")\r\n \
        *country - Filter results to only show a specific country or countries (e.g. "Netherlands")\r\n \
        *domain - Filter results to only show a specific domain (e.g. "example.com")',dest='filterType')
    optArgs.add_argument('-x','--exclude',required=False,help='Tells LoggrJack to exclude a specific value from overall results (requires the -d parameter):\r\n \
        *user - Remove a specific user or users from the overall results ("e.g. andytaylor@example.com")\r\n \
        *ip - Remove a specific IP address or addresses from the overall results (e.g. "1.2.3.4")\r\n \
        *country - Remove a specific country or countries from the overall results (e.g. "Netherlands")\r\n \
        *domain - Remove a specific domain from the overall results (e.g. "example.com")',dest='excludeType')
    optArgs.add_argument('-d','--data',required=False,help='Passes specific data for filtering or exclusion of results; multiple, comma-separated values can be provided',dest='modifierData')

    ## Parse args and confirm the user hasn't passed conflicting arguments. Also, if
    ## the user has passed a user in DOMAIN\USERNAME format, the backslash (\) needs
    ## to be escaped properly or it won't carry through the script.

    args = parser.parse_args()
    argCheck(args)

    if args.modifierData and "\\" in args.modifierData:
        args.modifierData = args.modifierData.replace("\\","\\\\")

    ## Disable coloration of terminal output if the user doesn't want it

    if args.noColor:
        txtColor.colGood = txtColor.colInfo = txtColor.colWarn = txtColor.colErr = txtColor.colNorm = "\033[0m"

    ## Print version information if it's in the args

    if args.printVer:
        printVer()
        sys.exit()

    ## Set verbosity level

    if args.verbOut:
        verbLvl = args.verbOut
    else:
        verbLvl = 0

    ## Attempt to locate and open log file designated by the user

    fileLoc = os.path.abspath(args.LogFile)
    geoLoc = os.path.abspath(args.DBFile)

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open log file at " + fileLoc, end='\r')

    try:
        fileText = open(fileLoc,'r').readlines()
    except:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open log file at " + fileLoc + " - " + txtColor.colWarn + "FAILED" + txtColor.colNorm)
        print("[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Unable to open the log file, possibly because it wasn't where you said it would be. Please check the file path and try again.")
        sys.exit()

    ## Attempt to locate and open MaxMind database file designated by the user

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open log file at " + fileLoc + " - " + txtColor.colGood + "SUCCESS" + txtColor.colNorm)
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open GeoIP database at " + geoLoc, end='\r')

    try:
        cityList = geoip2.database.Reader(geoLoc)
    except:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open GeoIP database at " + geoLoc + " - " + txtColor.colWarn + "FAILED" + txtColor.colNorm)
        print("[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Unable to open the geolocation database, possibly because it wasn't where you said it would be. Please check the file path and try again.")
        sys.exit()

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to open GeoIP database at " + geoLoc + " - " + txtColor.colGood + "SUCCESS" + txtColor.colNorm)

    ## Since necessary files can be accessed, mark analysis start time

    aStartTime = datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S")

    ## Hash the log file for integrity

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to generate hash of log file", end='\r')

    try:
        fileBytes = open(fileLoc,'rb').read()
        fileHash = hashlib.sha256(fileBytes).hexdigest()
        if verbLvl > 1:
            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to generate hash of log file - " + txtColor.colGood + "SUCCESS" + txtColor.colNorm)
    except:
        fileHash = "Unknown - Error in calculation"
        if verbLvl > 1:
            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to generate hash of log file - " + txtColor.colWarn + "FAILED" + txtColor.colNorm)

    ## If the user hasn't explicity passed their current location, attempt to determine it based on public IP address

    if not args.warnIP or args.warnIP == "getDefault":

        ### Check to see if the user wants to check public IP against a specific site (-M)

        if args.myIP:
            ipSite = args.myIP
        else:
            ipSite = 'icanhazip.com'

        ### Initiate call to the designated site

        if verbLvl > 1:
            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to determine user geolocation (using " + ipSite + ")", end='\r')

        currLoc = whereAmI(cityList,ipSite)

        ### If the location couldn't be determined for some reason, set it as US and create the info string

        if currLoc == "Unknown":
            currLoc = 'United States'
            if verbLvl > 1:
                print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to determine user geolocation (using " + ipSite + ") - " + txtColor.colWarn + "FAILED" + txtColor.colNorm)
        else:
            if verbLvl > 1:
                print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to determine user geolocation (using " + ipSite + ") - " + txtColor.colGood + "SUCCESS" + txtColor.colNorm)

    else:
        currLoc = args.warnIP

    locMsg = "Current location: " + str(currLoc)

    ## Identify the user's log type selection, set the extraInfo labels for the resultsOut function
    ## and initiate the necessary parsers

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to parse all events from log file", end='\r')

    try:

        if args.logType == '1':

            logFileType = "Microsoft 365 Auth (User Logged In)"
            extInfLbl.extInfLbl1 = "User Type"
            extInfLbl.extInfLbl2 = "Record Type"
            extInfLbl.extInfLbl3 = "User GUID"

            eventDict = parseO365Auth(fileText, verbLvl, args.privIP, args.logGarbage) # Parse the events into a dict

        elif args.logType == '2':

            logFileType = "Microsoft 365 (All Events)"
            extInfLbl.extInfLbl1 = ""
            extInfLbl.extInfLbl2 = ""
            extInfLbl.extInfLbl3 = ""

            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Microsoft 365 general log parsing will be available in a future release.")
            sys.exit()

        elif args.logType == '3':

            logFileType = "Azure Active Directory"
            extInfLbl.extInfLbl1 = ""
            extInfLbl.extInfLbl2 = ""
            extInfLbl.extInfLbl3 = ""

            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Azure Active Directory log parsing will be available in a future release.")
            sys.exit()

        elif args.logType == '4':

            logFileType = "Microsoft IIS (W3C Format)"
            extInfLbl.extInfLbl1 = "IIS URI Stem"
            extInfLbl.extInfLbl2 = "Client User-Agent String"
            extInfLbl.extInfLbl3 = "HTTP Method & Response Code"

            eventDict = parseIIS(fileText, verbLvl, args.privIP, args.logGarbage, args.eDomain) # Parse the events into a dict

        elif args.logType == '5':

            logFileType = "Debian Auth.log (All Events)"
            extInfLbl.extInfLbl1 = ""
            extInfLbl.extInfLbl2 = ""
            extInfLbl.extInfLbl3 = ""

            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Debian auth log parsing will be available in a future release.")
            sys.exit()

    except:

        if verbLvl > 1:
            print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to parse all events from log file - " + txtColor.colWarn + "FAILED" + txtColor.colNorm + "\r\n")
        print("[" + txtColor.colErr + "ERROR" + txtColor.colNorm + "] Failed to parse events from the log file provided. Exiting.")
        sys.exit()

    if verbLvl > 1:
        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Attempting to parse all events from log file - " + txtColor.colGood + "SUCCESS" + txtColor.colNorm + "\r\n")

    ## Extract the date and time of the first and last event from eventDict for the upcoming header

    dtInfo = parseDates(eventDict)

    ## Create filerDict, which is the user's config for filtering results

    filterDict = getFilterDict(args)

    print("*" * 88)
    print("Analysis start time (UTC): " + aStartTime)
    print("Log file name: " + os.path.split(args.LogFile)[1])
    print("Log file type: " + logFileType)
    print("Log file hash (SHA256): " + fileHash)
    print("Earliest event in log (UTC): " + str(dtInfo[0]))
    print("Latest event in log (UTC): " + str(dtInfo[1]))
    print(locMsg)
    print(filterDict["outAction"])
    print("-" * 88)
    print("Filters:")
    print(filterDict["userString"])
    print(filterDict["ipString"])
    print(filterDict["ctryString"])
    print(filterDict["domainString"])
    print(filterDict["evntString"])
    print(("*" * 88) + "\r\n")

    if args.kCity or args.filterType or args.excludeType or args.logGarbage or args.privIP:

        print("[" + txtColor.colErr + "WARN" + txtColor.colNorm + "] Use of certain filters (-k, -f, -x, -g, -P) may cause relevant events to be omitted")

    ## If the user passed the -i parameter, initiate IP sort and dump

    if args.lIPs:

        print("["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] Printing unique IP addresses from this log file\r\n")

        countIPs = dumpIPs(eventDict,verbLvl,cityList,currLoc,args.privIP)

    ## If the user passed the -s parameter, initiate the summary process

    elif args.topNum:

        print("["+ txtColor.colInfo + "INFO" + txtColor.colNorm + "] Printing IP and user summary from this log file\r\n")

        topCount = args.topNum # The top number of IPs requested by user
        if args.hibpAPIKey:
            hibpKey = args.hibpAPIKey # User's API key for HaveIBeenPwned
        else:
            hibpKey = "None" # No API key provided

        createSummary(eventDict,topCount,cityList,currLoc,verbLvl,hibpKey)

    ## If the user didn't pass any args, or passed only filtering / exclusion args, do the normal thing

    else:

        print("[" + txtColor.colInfo + "INFO" + txtColor.colNorm + "] Printing line-by-line authentication activity from this log\r\n")

        detailedAnalysis(eventDict,cityList,args,currLoc,verbLvl)

    ## Close out with some statistical information

    print("\r\n" + ("*" * 88))
    print(filterDict["outAction"].split(":")[1].strip(" ") + " complete. Exiting.")
    print("Analysis complete time (UTC): " + datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S"))
    print("Total events logged: " + str(f'{globalRes.resTotal:,}'))
    if filterDict["outAction"].split(":")[1].strip(" ") == "Detailed Analysis":
        print("Total events analyzed: " + str(f'{globalRes.resProc:,}'))
        print("Total events printed: " + str(f'{globalRes.resPrint:,}'))
    if filterDict["outAction"].split(":")[1].strip(" ") == "IP dump":
        print("Unique IPv4 addresses found: " + str(countIPs[0]))
        print("Unique IPv6 addresses found: " + str(countIPs[1]))
    print(("*" * 88) + "\r\n")

if __name__ == "__main__":
    main()
