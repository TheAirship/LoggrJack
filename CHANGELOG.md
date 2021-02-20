1.3.0

* Added ability to parse Microsoft IIS logs (W3C format)
* Added ability to filter out internal / private IP addresses during the parsing
* Added ability to designate the site used to determine current public IP, instead of forcing icanhazip.com
* Added ANSI text coloration to highlight certain events and notifications
* Improved 'garbage' event filtering to create cleaner output
* Improved certain regex search patterns for parsing usernames and GUIDs
* Improved status messages printed at higher verbosity levels
* Modified date / time parsing in some functions to create consistency with others
* Fixed a bug that caused the analyzed and printed event counters to be higher than they actually were
* Fixed a bug that caused internal / private IP addresses to be flagged as foreign addresses
* Fixed a bug that caused the HIBP function to return some breach data types multiple times for a single account
* Fixed a bug that caused some filter or exclusion data to be ignored because of case sensitivity
* Minor grammatical, formatting, and spelling corrections

1.2.0

* Initial public release.
