# LoggrJack - Simplify Text-Based Log Analysis

LoggrJack is a log parsing and analytics tool written in Python. It was created to apply geolocation data to Office 365 authentication logs and grew into something more. There are two general use cases for this tool:

* To help incident responders quickly summarize an authentication log as part of response efforts.
* To help syadmins and IT personnel quickly audit authentication logs for suspicious activity. This could, in theory, result in the aforementioned use case.

With LoggrJack, you can:

* Export a summary of authentication activity from a log file, including:
  * The top 10 source IPv4 and IPv6 addresses seen in the log
  * A list of IP addresses that do not geolocate to the user's current region
  * A per-user summary of authentication activity, including the number of times they authenticated and their geolocation
* Export a line-by-line analysis of activity from the log in chronological order, with geolocation applied
* Filter analysis to a specific user, IP address, country, or domain
* Query the Have I Been Pwned API for the Pwned status of each email address
* Dump a list of all unique IPv4 and IPv6 addresses seen in the log file

LoggrJack is not meant to replace a SIEM or any other more advanced security event monitoring tool.

## Installation & General Use

LoggrJack can be run from just about any system with Python installed. Use of a Python virtual environment, such as pyenv (https://github.com/pyenv/pyenv) with the virtualenv plugin, is recommended.

1. Clone the repo: `$ git clone https://github.com/TheAirship/LoggrJack.git`
2. Change to the directory: `$ cd [path_to_download]`
3. Install the reqs
    * Using pip (python3 already installed): `$ pip install -r requirements.txt`
    * Using apt: `$ sudo apt install python3 python3-geoip2 python3-ipwhois python3-requests`
4. Download a copy of the most current MaxMind GeoLite2 City database in mmdb format (learn how to do that here: https://dev.maxmind.com/geoip/geoip2/geolite2/)
5. Download a copy of the log file you want to analyze (see the *Compatible Logs* section below)
6. Run LoggrJack, targeting the downloaded log file and MaxMind database

Alternatively, if you are on a Windows platform, you can download the EXE from the latest release instead of cloning the repo and installing requirements. In this case you would replace `python LoggrJack.py` with `LoggrJack.exe` in all command examples below.

## Compatible Logs

At this time, LoggrJack is only built to parse authentication logs from Office 365 (**Workplace Analytics > User Logged In**). Depending on the size of your environment and the level of user activity, certain LoggrJack configurations may produce a substantial amount of output. In general, start with a week's worth of exported events and then adjust from there. You can learn more about exporting Office 365 logs here: https://docs.microsoft.com/en-us/microsoft-365/compliance/search-the-audit-log-in-security-and-compliance?view=o365-worldwide

The ultimate goal of the LoggrJack project is to include other text-based log formats (e.g. OWA / IIS, Azure Active Directory, Debian auth), allowing for an at-a-glance review of activity for different systems and applications.

## Commands, Tips, and Examples

LoggrJack has three analysis modes: Log Summary, Detailed Analysis, and IP Dump.

![helpimage](https://github.com/TheAirship/LoggrJack/blob/main/Images/LJ%20-%20Help.png)

### Log Summary

The easiest place to start with LoggrJack is the Log Summary mode, which summarizes the data from the log, including top 10 IPv4 addresses, top 10 IPv6 addresses, IP addresses that don't geolocate to the user's current country, and a summary of authentication data for each user.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s`

You can also modify the top *n* addresses that are included in the summary by passing an integer with the -s parameter. For example, to show only the top 7 IPv4 and IPv6 addresses:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s 7`

To add Have I Been Pwned breach data for each email address found in the log, first obtain your API key from https://haveibeenpwned.com/API/Key, then pass it to LoggrJack using the -p parameter. You can increase the verbosity (-v or -vv) for more detailed breach information.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s -p [HIBP API Key]`

### Detailed Analysis

LoggrJack's Detailed Analysis will create a line-by-line, chronological listing of authentication events, including date, time, username, source IP, and country data.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file]`

Filtering core analysis output is easy. You simply tell LoggerJack what data (i.e. user, IP, or country) you want to filter by and pass a comma-separated list of values to filter. For example, to filter all results to user 'andytaylor@example.com', use the following:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f user -d "andytaylor@example.com"`

Or, to filter by IP addresses x.x.x.x and y.y.y.y:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f ip -d "x.x.x.x,y.y.y.y"`

You can also exclude specific values from the results using the -x parameter and similar command formatting.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -x country -d "United States,Canada"`

Finally, you can filter or exclude a specific domain if you have multiple domains in your logs. As an example, to only show domains other than example.com:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -x domain -d "example.com"`

NOTE: You cannot pass both the -f and -x parameters in the same command.

Additional verbosity (-v through -vvv) will return other information, such as the reported login type, and the results of a WHOIS lookup for the IP address. Use caution, because higher verbosity levels also means much more output. You should consider filtering the full output (e.g. by user, IP, or country) if greater verbosity is desired while using the Detailed Analysis mode.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f user -d "barneyfife@example.com" -vvv`

### IP Dump

To dump a list of all unique IP addresses found in the log file, use the -i parameter. Increased verbosity (-v or -vv) will add geolocation info to each IP address.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -i`

### Other Options

Some Office 365 logs include events that are benign and only clutter the log, such as FaultDomainRedirect. You can filter out these events for a cleaner log analysis with the -g parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -g`

Finally, to quick filter down to IPs that geolocate to areas outside of your current country, you can use the -w parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -w`

## Caveats & Reminders

* **IP geolocation isn't always 100% accurate.** Geolocation information also changes constantly. Be sure to use the most current MaxMind database available, and understand that you aren't going to get an exact city, region, and country result every time.
* **Attribution is hard.** Just because the source IP of an auth attempt geolocates to a specific country doesn't mean that it's actually where the attacker is located. Geolocation information is provided to help spot unusual or suspicious activity, not to catch a bad actor.
* **Log formats change periodically.** Also, my coding is far from perfect. If you encounter bugs or unexpected results after running LoggrJack, please submit an issue on GitHub.
* LoggrJack was written using the free MaxMind GeoLite2 City database in mmdb format. Other MaxMind GeoLite2 databases may still work at lower verbosity levels. GeoLite2 databases in CSV format will not work; make sure you download the mmdb format.
* LoggrJack was written in python3, and tested primarily on 3.9.0.

### Internet Connectivity

LoggrJack uses your Internet connection to determine your current location, to execute WHOIS lookups, and to pull down data from Have I Been Pwned. If you don't want to connect to the Internet, or a connection is unavailable...

* Do not use verbosity level -vvv with the Detailed Analysis mode
* Do not use the -p parameter to query Have I Been Pwned
* Manually override the geolocation warning function by passing your current country as an argument with the -w parameter, as shown below:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -w "Great Britain"`

## About / License

Thanks to [@MaxMind](https://github.com/maxmind) for their excellent work giving locations to IPs.\
Thanks to [@TroyHunt](https://github.com/troyhunt) for his excellent work on Have I Been Pwned?\
Thanks to the many, many people who put time and effort into developing the modules used in LoggrJack.\
\
Questions, comments, and suggestions for improvement are welcome. Contact: infosec@theairship.cloud\
Licensed under [Apache License 2.0](https://github.com/TheAirship/LoggrJack/blob/main/LICENSE)
