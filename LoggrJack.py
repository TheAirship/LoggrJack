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
import datetime
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
__version__ = "1.2.0"

# Set global variables

class globalRes():

    """
    The results counters (total, printed, and processed)
    """

    resTotal = 0 # Total events in loaded log file
    resProc = 0 # Events processed after log cleanup (-g parameter)
    resPrint = 0 # Events printed after user-defined filters / exclusions

# Set dict variables with relevant log info
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

# Functions

def printBanner():

    """
    Function: Print a delightful banner
    Called from: main
    """

    theLogo = """
                  _                                   _            _
                 | |    ___  __ _  __ _  ___  _ _  _ | | __ _  __ | |__
                 | |__ / _ \/ _` |/ _` |/ -_)| '_|| || |/ _` |/ _|| / /
                 |____|\___/\__, |\__, |\___||_|   \__/ \__,_|\__||_\_\\
                            |___/ |___/
                                  Version: {}
    """.format(__version__)

    print(theLogo)

def printVer():

    """
    Function: Prints detailed version info
    Called from: main
    """

    print("LoggerJack - Log Parsing and Analytics tool")
    print("Version " + __version__)
    print("Created by " + __author__ + "\r\n")

def argCheck(args):

    """
    Function: Checks the args passed by the user to confirm there aren't any conflicts
    Called from: main
    """

    ## If only the version is being printed, all other arg checks can be skipped

    if not args.printVer:

        ### Log file (-l) and geolocation database (-m) arguments are always required unless the detailed version is being printed

        if not args.LogFile and not args.DBFile:
            print ("\r\n[ERROR] You must pass the log file (-l) and geolocation database file (-m) with each analysis. Please try again.\r\n")
            sys.exit()

        ### IP dump (-i) and the log summary (-s) can't be passed simultaneously

        if (args.lIPs and args.topNum):
            print ("\r\n[ERROR] You cannot pass both the IP dump (-i) arguments and the summary function (-s) arguments simultaneously. Please select one and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) can't be passed simultaneously

        if (args.filterType and args.excludeType):
            print ("\r\n[ERROR] You cannot pass both filter (-d) and exclude (-x) arguments simultaneously. Please select one and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) require the data (-d) parameter

        if ((args.filterType or args.excludeType) and not args.modifierData):
            print("\r\n[ERROR] Use of the filter (-f) and exclude (-x) arguments requires the Modifier Data (-d) argument. Please include the -d parameter and try again.\r\n")
            sys.exit()

        ### Filter (-f) and exclude (-x) arguments can only be one of four values

        if args.filterType:
            filterTest = args.filterType.lower()
            if (filterTest != "user") and (filterTest != "ip") and (filterTest != "country") and (filterTest != "domain"):
                print("\r\n\[ERROR] The filter (-f) argument can only be one of four values (i.e. 'user', 'ip', 'country', 'domain').\r\n")
                sys.exit()

        if args.excludeType:
            excludeTest = args.excludeType.lower()
            if (excludeTest != "user") and (excludeTest != "ip") and (excludeTest != "country") and (excludeTest != "domain"):
                print("\r\n\[ERROR] The exclude (-x) argument can only be one of four values (i.e. 'user', 'ip', 'country', 'domain').\r\n")
                sys.exit()

        ### Have I Been Pwned lookups (-p) require the summary function (-s) parameter

        if args.hibpAPIKey and not args.topNum:
            print("\r\n[ERROR] Have I Been Pwned lookups (-p) can only be passed with the log summary function (-s). Please select both and try again.\r\n")
            sys.exit()

def catchSigs(signum, frame):

    """
    Function: Catch SIGINTs and other fun things
    Called from: main
    """

    ## Calculate the number of processed events vs the total calculated from the log

    remEvt = globalRes.resProc / globalRes.resTotal
    remPerc = "{:.2%}".format(remEvt)

    ## Print completion stats to screen and exit

    print("\r\n[INFO] Caught a Keyboard Interrupt. Exiting with " + str(globalRes.resProc) + " of " + str(globalRes.resTotal) + " (" + remPerc + ") events processed.")
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

    ## Determine if results will be filtered or excluded by user & create output string

    try:
        if args.filterType.lower() == "user" or args.excludeType.lower() == "user":
            for i in range(0,(len(modData))):
                if userString == "":
                    userString = modData[i]
                else:
                    userString = userString + ", " + modData[i]
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

def parseDates(fileText):

    """
    Function: Extracts the earliest and latest events from the logs (in UTC) and makes them readable
    Called from: main
    """

    eventDates = []
    eventTimes = []

    ## Cycle through all line items, exctract dates, and add to dictionary

    for i in range(2,len(fileText)-1):
        eventDates.append(fileText[i].split(",")[0])

    ## Get the earliest and latest dates using the min and max functions, then format using DateTime

    earlyDate = min(eventDates)
    cleanEarlyDate = datetime.datetime.strptime(earlyDate[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%m/%d/%Y, %H:%M:%S')
    lateDate = max(eventDates)
    cleanLateDate = datetime.datetime.strptime(lateDate[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%m/%d/%Y, %H:%M:%S')

    return cleanEarlyDate, cleanLateDate

def parseO365(fileText, it, verbOut):

    """
    Function: Parses an O365 event log for use with LoggerJack's core function
    Called from: detailedAnalysis
    """

    ## Set relevant event variables by splitting relevant log text

    lineDateTime = fileText[it].split(",")[0]
    lineIP = fileText[it].split(",")[13].split("\"")[6]
    lineUserType = fileText[it].split("{")[1].split(",")[7].split(":")[1]
    lineRecordType = fileText[it].split("{")[1].split(",")[4].split(":")[1]
    lineGUID = fileText[it].split("{")[1].split(",")[12].split(":")[1].replace("\"","")

    ## Office 365 sometimes uses a GUID-style string in the UserID column instead of
    ## an email address. This can be confusing during analysis. This section attempts to locate the
    ## email address from a separate part of the logged event if the GUID is found the normal UserID column

    if not "@" in fileText[it].split(",")[1] and "@" in fileText[it].split("{")[1].split(",")[6].split(":")[1].replace("\"",""):
        if verbOut != 0:
            lineUser = fileText[it].split("{")[1].split(",")[6].split(":")[1].replace("\"","") + " (converted from user GUID)"
        else:
            lineUser = fileText[it].split("{")[1].split(",")[6].split(":")[1].replace("\"","")
    else:
        lineUser = fileText[it].split(",")[1]

    return [lineDateTime,lineIP,lineUser,lineUserType,lineRecordType,lineGUID]

def geoLook(lineIP,cityList):

    """
    Function: Provides the city and country location for a given IP address
    Called from: whereAmI, createSummary, dumpIPs, detailedAnalysis
    """

    eventGeo = []

    ## GeoIP doesn't always handle shortened IPv6 addresses correclty, so they need to be expanded

    if ":" in lineIP:
        lineIP = ipaddress.ip_address(lineIP).exploded

    ## Check for RFC 1918 addressing using (admittedly bad) regex

    if ((re.match(r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'172\.(?:1[6-9]|2[0-9]|3[0-2])\.\d{1,3}\.\d{1,3}',lineIP)) or
        (re.match(r'192\.168\.\d{1,3}\.\d{1,3}',lineIP))):
        geoInfo = ["No City","No State","RFC1918 (Private) Address"]
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

            eventGeo = ["GEOLOCATION","ERROR","UNKNOWN - GEOLOCATION ERROR"]

    return eventGeo

def whereAmI(cityList):

    """
    Function: Attempts to identify the user's current country so it can be used for reference
    Called from: main
    """

    try:

        ### Try to get public IP, then use it to call the geoLook function
        ### If successful, get the current country name and pass it back

        currIPcall = requests.get('https://icanhazip.com')
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

    ## Wait for 1 second so as not to be a burden or stack up HIBP queries

    time.sleep(float(1.5))

    ## Create necessary request strings

    baseReqStr = "https://haveibeenpwned.com/api/v3/breachedaccount/" + uName
    headerDict = {'hibp-api-key':hibpKey,'user-agent':'LoggerJack ' + __version__ + ' (Linux / Mac / Win)'}

    ## Query HIBP and parse based on HTTP response code

    try:
        breachResp = requests.get(baseReqStr,headers=headerDict)

        if breachResp.status_code == 200:
            breachData = breachResp.json()
        elif breachResp.status_code == 401:
            breachData = "[ERROR] The HIBP API key provided was not valid."
        elif breachResp.status_code == 404:
            if verbLvl > 0:
                breachData = "[OK] No breaches associated with this account."
            else:
                breachData = "[OK]"
        elif breachResp.status_code == 429:
            breachData = "[ERROR] The HIBP rate limit has been exceeded."
        elif breachResp.status_code == 503:
            breachData = "[ERROR] The HIBP service is unavailable."

    except:
        breachData = "[ERROR] Unable to query HIBP database. Check your Internet connection."

    return breachData

def createSummary(fileText,topNum,cityList,currLoc,verbLvl,hibpKey):

    """
    Function: Summarizes the data in the log file by top IPs and all users (per the -s parameter)
    Called from: main
    """

    ## Part 1 dumps the top IP addresses (10 by default) by number of accesses

    allIPv4s = []
    allIPv6s = []

    ## Loop through extracted log line data and add IPs addresses to the respective lists

    for i in range(2,len(fileText)-1):
        eventData = parseO365(fileText,i,verbLvl)
        lineIP = eventData[1]
        if "." in lineIP:
            allIPv4s.append(lineIP)
        else:
            allIPv6s.append(lineIP)

    ## Created sorted Counter dictionary in decsending (most to least hits) order

    sortedIPv4s = sorted(((value,key) for (key,value) in Counter(allIPv4s).items()),reverse=True)
    sortedIPv6s = sorted(((value,key) for (key,value) in Counter(allIPv6s).items()),reverse=True)

    ## Print output. If the user entered a 'top n' number that's greater than the length of the list,
    ## lower it (topNum variable) to the length of the list to dodge index errors

    print ("[INFO] The top " + str(topNum) + " most frequent IPv4 source addresses are:")

    if topNum > len(sortedIPv4s):
        topNum = len(sortedIPv4s)

    for i in range(0,topNum):
        print (sortedIPv4s[i][1] + " - " + str(sortedIPv4s[i][0]) + " hit(s)")

    print ("\r\n[INFO] The top " + str(topNum) + " most frequent IPv6 source addresses are:")

    if topNum > len(sortedIPv6s):
        topNum = len(sortedIPv6s)

    for i in range(0,topNum):
        print (sortedIPv6s[i][1] + " - " + str(sortedIPv6s[i][0]) + " hit(s)")

    ## Part 2 checks through all IPs and provides notification when an IP doesn't align with the current country
    ## foundOne is used to notify the user if no results are found from this section

    foundOne = False

    print ("\r\n[INFO] The following source IP addresses did NOT geolocate to your current country:")

    ## Cycle through each line data item, pull the geolocation, and see if it matches the user's current location

    for i in range(0,len(sortedIPv4s)):
        ipGeo = geoLook(sortedIPv4s[i][1],cityList)
        if ipGeo[2] != currLoc:
            print(sortedIPv4s[i][1] + " (" + ipGeo[0] + ", " + ipGeo[1] + ", " + ipGeo[2] + ") - " + str(sortedIPv4s[i][0]) + " hit(s)")
            foundOne = True

    for i in range(0,len(sortedIPv6s)):
        ipGeo = geoLook(sortedIPv6s[i][1],cityList)
        if ipGeo[2] != currLoc:
            print(sortedIPv6s[i][1] + " (" + ipGeo[0] + ", " + ipGeo[1] + ", " + ipGeo[2] + ") - " + str(sortedIPv6s[i][0]) + " hit(s)")
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
            headerDict = {'hibp-api-key':hibpKey,'user-agent':'LoggerJack ' + __version__ + ', Linux / Mac / Win)'}
            allBreaches = requests.get(baseReqStr,headers=headerDict)
            allBreaches = allBreaches.json()

    ## Proceed with the rest of part 3

    print("\r\n[INFO] Summarizing all user activity from this log:")

    userDict = {}

    ## Build the user dictionary with users as key and a list of IPs as the value

    globalRes.resProc = 2 # Set at 2 to account for removed lines from the log file

    for i in range(2,len(fileText)-1):
        eventData = parseO365(fileText,i,verbLvl)
        lineIP = eventData[1]
        lineUser = eventData[2]

        if not lineUser in userDict.keys():
            userDict[lineUser] = [lineIP]
        else:
            if not isinstance(userDict[lineUser],list):
                ##### Convert value of existing dictionary entry to a list to accomodate multiple entries
                userDict[lineUser] = [userDict[lineUser]]
            userDict[lineUser].append(lineIP)

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

        reportStr = "User " + userName + " - " + str(len(ipList)) + " authentication(s) from " + geoList[0]

        ### If necessary, add additional source countries, then print the output

        for i in range(1,len(geoList)):
            reportStr = reportStr + ", " + geoList[i]

        print (reportStr)

        ### If the user has provided an API key for HaveIBeenPwned, submit and parse the request, then print the result

        if hibpKey != "None":

            #### Have I Been Pwned only allows searches of email addresses
            #### Check for validity of username, which is stored in thisKey variable

            #### Some usernames may have other text added that needs to be removed depending on the verbosity level

            if "(" in thisKey:
                thisKey = thisKey.split("(")[0].strip()

            if not re.fullmatch(emailCheck,thisKey.lower()):
                print("    *HIBP Status: [ERROR] Username doesn't appear to be a valid email address.")
            else:

                userBreach = getHIBP(thisKey,hibpKey,verbLvl)

                if ("[OK]" in userBreach) or ("[ERROR]" in userBreach):
                    print("    *HIBP Status: " + userBreach)
                else:
                    if verbLvl == 0:
                        print("    *HIBP Status: [PWNED]")
                    if verbLvl == 1:
                        print("    *HIBP Status: [PWNED] User account found in " + str(len(userBreach)) + " breaches.")
                    elif verbLvl > 1:
                        print("    *HIBP Status: [PWNED] User account found in the following " + str(len(userBreach)) + " breaches:")

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

                            if "Password" in allBreaches[breachIdx]['DataClasses']:
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
                                if (len(breachStr) == 0) and not (allBreaches[breachIdx]['DataClasses'][dType] in breachStr):
                                    breachStr = allBreaches[breachIdx]['DataClasses'][dType]
                                elif not (allBreaches[breachIdx]['DataClasses'][dType] in breachStr):
                                    breachStr = breachStr + ", " + allBreaches[breachIdx]['DataClasses'][dType]

                            ######## Add the breach name to the front and print the final output string

                            breachStr = breachName + " - " + breachStr
                            print("        -" + breachStr)

def dumpIPs(fileText,verbLvl,cityList):

    """
    Function: Dumps only a sorted list of unique IPs (per the -i parameter)
    Called from: main
    """

    allIPv4s = []
    allIPv6s = []
    allIPs = []

    ## Loop through extracted log text and add addresses to IPv4 or IPv6 lists

    for i in range(2,len(fileText)-1):
        lineIP = fileText[i].split(",")[13].split("\"")[6]
        if "." in lineIP:
            allIPv4s.append(lineIP)
        else:
            allIPv6s.append(lineIP)

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
        if verbLvl > 0:
            lineGeo = geoLook(allIPs[i],cityList)

            if verbLvl == 1:
                print(allIPs[i] + " (" + lineGeo[2] + ")")

            if verbLvl > 1:
                print(allIPs[i] + " (" + lineGeo[0] + ", " + lineGeo[1] + ", " + lineGeo[2] + ")")

        else:
            print(allIPs[i])

    return [len(sortedIPv4s),len(sortedIPv6s)]

def detailedAnalysis(fileText,cityList,args,currLoc):

    """
    Function: Parses the event log line by line and provides an ordered, filtered output with geolocation info added
    Called from: main
    """

    eventDict = {}
    globalRes.resProc = 2 # Set at 2 to account for header lines from the log file
    globalRes.resPrint = 2 # Set at 2 to account for header lines from the log file

    for i in range(2,len(fileText)-1):

        #First confirm that this event shouldn't be thrown out for having garbage text

        if args.logGarbage:
            if "FaultDomainRedirect" in fileText[i]:
                continue

        #Send the fileText variable to the correct parser with the current iterator number

        lineData = parseO365(fileText,i,args.verbOut)

        #Transcribe the values from the returned lineData list to variables that make sense

        lineDateTime = lineData[0]
        lineIP = lineData[1]
        lineUser = lineData[2]
        lineUserType = lineData[3] + " - " + logUserType[lineData[3]]
        lineRecordType = lineData[4] + " - " + logRecordType[lineData[4]]
        lineGUID = lineData[5]

        if not lineDateTime in eventDict.keys():
            eventDict[lineDateTime] = [lineUser,lineIP,lineUserType,lineRecordType,lineGUID]
        else:
            if not isinstance(eventDict[lineDateTime][0],list):
                ####Convert value to a list to accomodate multiple values per key
                eventDict[lineDateTime] = [eventDict[lineDateTime]]
            eventDict[lineDateTime].append([lineUser,lineIP,lineUserType,lineRecordType,lineGUID])

    ##Sort event dictionary by earliest to latest event, then extract relevant data

    for thisKey in sorted(eventDict.keys()):
        if isinstance(eventDict[thisKey][0],list):
            for eachVal in range(0,len(eventDict[thisKey])):
                eventDate = datetime.datetime.strptime(thisKey[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%m/%d/%Y')
                eventTime = datetime.datetime.strptime(thisKey[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%H:%M:%S')
                eventUser = eventDict[thisKey][eachVal][0]
                eventIP = eventDict[thisKey][eachVal][1]
                eventUType = eventDict[thisKey][eachVal][2]
                eventRType = eventDict[thisKey][eachVal][3]
                eventUGUID = eventDict[thisKey][eachVal][4]
                eventGeo = geoLook(eventIP, cityList)
                eventInfo = [eventDate,eventTime,eventUser,eventGeo[0],eventGeo[1],eventGeo[2],eventIP,eventUType,eventRType,eventUGUID]

                resultsOut(eventInfo,args,currLoc)

        else:
            eventDate = datetime.datetime.strptime(thisKey[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%m/%d/%Y')
            eventTime = datetime.datetime.strptime(thisKey[:-2], '%Y-%m-%dT%H:%M:%S.%f').strftime('%H:%M:%S')
            eventUser = eventDict[thisKey][0]
            eventIP = eventDict[thisKey][1]
            eventUType = eventDict[thisKey][2]
            eventRType = eventDict[thisKey][3]
            eventUGUID = eventDict[thisKey][4]
            eventGeo = geoLook(eventIP, cityList)
            eventInfo = [eventDate,eventTime,eventUser,eventGeo[0],eventGeo[1],eventGeo[2],eventIP,eventUType,eventRType,eventUGUID]

            resultsOut(eventInfo,args,currLoc)

def resultsOut(eventInfo,args,currLoc):

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
                if re.match(itemCheck, eventInfo[2]):   # Had to change to match from fullmatch because
                    eventMatch = True                   # of O365 UserIDs in some events
                    break
        elif args.filterType.lower() == "ip":
            for itemCheck in args.modifierData.split(","):
                if re.fullmatch(itemCheck, eventInfo[6]):
                    eventMatch = True
                    break
        elif args.filterType.lower() == "country":
            for itemCheck in args.modifierData.split(","):
                if re.fullmatch(itemCheck, eventInfo[5]):
                    eventMatch = True
                    break
        elif args.filterType.lower() == "domain":
            for itemCheck in args.modifierData.split(","):
                if "@" in eventInfo[2]:
                    if re.fullmatch(itemCheck, eventInfo[2].split("@")[1]):
                        eventMatch = True
                        break

    ## Exclude certain events containing info (-x) passed by the user

    elif args.excludeType:
        if args.excludeType.lower() == "user":
            for itemCheck in args.modifierData.split(","):
                if not re.match(itemCheck, eventInfo[2]):  # Had to change to match from fullmatch because
                    eventMatch = True                      # of O365 UserIDs in some events
                    break
        elif args.excludeType.lower() == "ip":
            for itemCheck in args.modifierData.split(","):
                if not re.fullmatch(itemCheck, eventInfo[6]):
                    eventMatch = True
                    break
        elif args.excludeType.lower() == "country":
            for itemCheck in args.modifierData.split(","):
                if not re.fullmatch(itemCheck, eventInfo[5]):
                    eventMatch = True
                    break
        elif args.excludeType.lower() == "domain":
            for itemCheck in args.modifierData.split(","):
                if "@" in eventInfo[2]:
                    if not re.fullmatch(itemCheck, eventInfo[2].split("@")[1]):
                        eventMatch = True
                        break

    ## Otherwise, the event automatically matches

    else:
        eventMatch = True

    ## If the event matches, print the output based on the verbosity level set by the user (-v)
    ## If it doesn't match, go back for the next event line

    if eventMatch == True:
        globalRes.resPrint += 1
        if args.verbOut == 1:
            print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[3] + ", " + eventInfo[4] + ", " + eventInfo[5] + ")")
        elif args.verbOut == 2:
            print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[3] + ", " + eventInfo[4] + ", " + eventInfo[5] + ")")
            print("    User GUID: " + eventInfo[9])
            print("    User Type: " + eventInfo[7])
            print("    Record Type: " + eventInfo[8])
        elif args.verbOut == 3:
            print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[3] + ", " + eventInfo[4] + ", " + eventInfo[5] + ")")
            print("    User GUID: " + eventInfo[9])
            print("    User Type: " + eventInfo[7])
            print("    Record Type: " + eventInfo[8])
            wiInfo = getWhois(eventInfo[6])
            if wiInfo == "WHOIS lookup failed.":
                print("    [ERROR] " + wiInfo)
            else:
                print("    IP ASN: " + wiInfo[0])
                print("    IP Registrar: " + wiInfo[1])
                print("    IP ASN Description: " + wiInfo[2])
                print("    IP Org Name: " + wiInfo[3])
        else:
            print(eventInfo[0] + ", " + eventInfo[1] + " - " + eventInfo[2] + " - " + eventInfo[6] + " (" + eventInfo[5] + ")")
    else:
        return

def main():

    """
    Function: Get after it
    Called from: N/A
    """

    ## Print the banner, including current version

    printBanner()

    ## Set the SIGINT handler to catch keyboard interrupts

    signal.signal(signal.SIGINT, catchSigs)

    ## Create args and arg parser

    parser = argparse.ArgumentParser(
        usage='python %s -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] [OPTIONS]' % sys.argv[0],
        add_help=False,
        description='LoggerJack - Simplify Text-Based Log Analysis',
        formatter_class=lambda prog: argparse.RawTextHelpFormatter(prog,max_help_position=45)
    )
    reqArgs = parser.add_argument_group('required arguments')
    optArgs = parser.add_argument_group('optional arguments')

    reqArgs.add_argument('-l','--log',required=False,help='Sets the path to the Office365 log file in CSV format',dest='LogFile')
    reqArgs.add_argument('-m','--mmdb',required=False,help='Sets the path to the MaxMind GeoIP2 database in mmdb format',dest='DBFile')

    optArgs.add_argument('-h','--help',help='Shows the command help',action='help')
    optArgs.add_argument('-V','--version',required=False,help='Prints version information',dest='printVer',action='store_true')
    optArgs.add_argument('-v','--verbose',required=False,help='Increases the verbosity of all output (e.g. printing city and region in addition to country)',default=0,dest='verbOut',action='count')
    optArgs.add_argument('-i','--ips',required=False,help='Dumps a list of all unique IP addresses found in the log file',dest='lIPs',action='store_true')
    optArgs.add_argument('-s','--summary',required=False,help='Provides a summary of the data found in the log file provided with the top n number of hits (default: 10)',type=int,dest='topNum',nargs='?',const=10)
    optArgs.add_argument('-k','--knowncity',required=False,help='Suppresses results that do not geolocate to a known city',dest='kCity',action='store_true')
    optArgs.add_argument('-w','--warning',required=False,help='Filters results to only show those from outside the current nation',dest='warnIP',nargs='?',type=str,const='getDefault')
    optArgs.add_argument('-g','--garbage',required=False,help='Removes events that are benign and clutter logs (e.g. auth redirects)',dest='logGarbage',action='store_true')
    optArgs.add_argument('-p','--pwned',required=False,help='Queries the HaveIBeenPwned API to determine if logged email addresses have been compromised in a breach (Requires API key)',dest='hibpAPIKey')
    optArgs.add_argument('-f','--filter',required=False,help='Tells GeO365 to filter results by a given value from the options shown below (requires the -d parameter):\r\n \
        *user - Filter results to only show a specific user or users ("e.g. andytaylor@foo.com")\r\n \
        *ip - Filter results to only show a specfic IP address or addresses (e.g. "1.2.3.4")\r\n \
        *country - Filter results to only show a specific country or countries (e.g. "Netherlands")\r\n \
        *domain - Filer results to only show a specific domain (e.g. "bar.com")',dest='filterType')
    optArgs.add_argument('-x','--exclude',required=False,help='Tells GeO365 to exclude a specific value from overal results (requires the -d parameter):\r\n \
        *user - Remove a specific user or users from the overall results ("e.g. andytaylor@foo.com")\r\n \
        *ip - Remove a specific IP address or addresses from the overall results (e.g. "1.2.3.4")\r\n \
        *country - Remove a specific country or countries from the overall results (e.g. "Netherlands")\r\n \
        *domain - Remove a specific domain from the overall results (e.g. "bar.com")',dest='excludeType')
    optArgs.add_argument('-d','--data',required=False,help='Passes the specific data for filtering or exclusion to LoggerJack; multiple, comma-separated values can be provided',dest='modifierData')

    ## Parse args and confirm the user hasn't passed conflicting arguments

    args = parser.parse_args()
    argCheck(args)

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
        print("[INFO] Attempting to open file at " + fileLoc + ".")

    try:
        fileText = open(fileLoc,'r').readlines()
    except:
        print("[ERROR] Unable to open the log file, possibly because it wasn't where you said it would be. Please check the file path and try again.")
        sys.exit()

    ## If successful, hash the log file too for integrity

    try:
        fileBytes = open(fileLoc,'rb').read()
        fileHash = hashlib.sha256(fileBytes).hexdigest()
    except:
        fileHash = "Unknown - Error in calculation"

    ## Attempt to locate and open MaxMind database file designated by the user

    if verbLvl > 1:
        print("[INFO] Log file loaded successfully!")
        print("[INFO] Attempting to open file at " + geoLoc + ".")

    try:
        cityList = geoip2.database.Reader(geoLoc)
    except:
        print("[ERROR] Unable to open the geolocation database, possibly because it wasn't where you said it would be. Please check the file path and try again.")
        sys.exit()

    if verbLvl > 0:
        print("[INFO] GeoIP database loaded successfully!\r\n")

    ## If the user hasn't explicity passed their current location, attempt to determine it based on public IP address

    if not args.warnIP or args.warnIP == "getDefault":
        currLoc = whereAmI(cityList)

        ### If the location couldn't be determined for some reason, set it as US and create the info string

        if currLoc == "Unknown":
            currLoc = "United States"

    else:
        currLoc = args.warnIP

    locMsg = "Current location: " + str(currLoc)

    ## Count the total number of events in the file and update the global variable

    globalRes.resTotal = len(fileText) - 1

    ## Parse start date, end date, and other general log info
    ## Also create filerDict, which is the user's config for filtering results

    dtInfo = parseDates(fileText)
    filterDict = getFilterDict(args)

    print("*" * 88)
    print("Analysis start time (UTC): " + datetime.datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S"))
    print("Log file name: " + os.path.split(args.LogFile)[1])
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

    if args.kCity or args.filterType or args.excludeType:
        print("[WARNING] Use of certain filters (-k, -f, -x) may cause relevant events to be omitted")

    ## If the user passed the -i parameter, initiate IP sort and dump

    if args.lIPs:

        print("[INFO] Printing unique IP addresses from this log file\r\n")

        countIPs = dumpIPs(fileText,verbLvl,cityList)

    ## If the user passed the -s parameter, initiate the summary process

    elif args.topNum:

        print("[INFO] Printing IP and user summary from this log file\r\n")

        topCount = args.topNum # The top number of IPs requested by user
        if args.hibpAPIKey:
            hibpKey = args.hibpAPIKey # User's API key for HaveIBeenPwned
        else:
            hibpKey = "None" # No API key provided

        createSummary(fileText,topCount,cityList,currLoc,verbLvl,hibpKey)

    ## If the user didn't pass any args, or passed only filtering / exclusion args, do the normal thing

    else:

        print("[INFO] Printing line-by-line authentication activity from this log\r\n")

        detailedAnalysis(fileText,cityList,args,currLoc)

    ## Close out with some statistical information

    print("\r\n" + ("*" * 88))
    print(filterDict["outAction"].split(":")[1].strip(" ") + " complete. Exiting.")
    print("Analysis complete time (UTC): " + datetime.datetime.utcnow().strftime("%m/%d/%Y, %H:%M:%S"))
    print("Total events analyzed: " + str(globalRes.resTotal))
    if filterDict["outAction"].split(":")[1].strip(" ") == "Detailed Analysis":
        print("Total events processed: " + str(globalRes.resProc))
        print("Total events matched: " + str(globalRes.resPrint))
    if filterDict["outAction"].split(":")[1].strip(" ") == "IP dump":
        print("Unique IPv4 addresses found: " + str(countIPs[0]))
        print("Unique IPv6 addresses found: " + str(countIPs[1]))
    print(("*" * 88) + "\r\n")

if __name__ == "__main__":
    main()
