# LoggrJack - Simplify Text-Based Log Analysis

LoggrJack is a tool written in Python that is meant to help incident responders, sysadmins, and other IT professionals quickly and efficiently analyze a variety of common text-based logs. It was originally created to apply geolocation data to Microsoft (Office) 365 authentication logs and grew from there. With LoggrJack, you can:

* Export a summary of activity (usually authentication data) from a log file, including:
  * The top 10 most frequent source IPv4 and IPv6 addresses seen in the log
  * A list of IP addresses that do not geolocate to the user's current country
  * A per-user summary of activity, including the total number of recorded events and the source geolocation for each
* Export a line-by-line analysis of activity from the log in chronological order, with geolocation applied
* Filter analysis to a specific user, IP address, country, or domain
* Query the Have I Been Pwned API for the Pwned status of any identified email addresses
* Dump a list of all unique IPv4 and IPv6 addresses seen in the log file, and apply geolocation if desired

LoggrJack is not meant to replace a SIEM or any other more advanced security event monitoring tool.

![helpimage](https://github.com/TheAirship/LoggrJack/blob/main/Images/LJExample.png)

## Installation & General Use

LoggrJack can be run from just about any system with Python installed. Use of a Python virtual environment, such as pyenv (https://github.com/pyenv/pyenv) with the virtualenv (https://github.com/pyenv/pyenv-virtualenv) plugin, is recommended.

1. Clone the repo: `$ git clone https://github.com/TheAirship/LoggrJack.git`
2. Change to the directory: `$ cd [path_to_download]`
3. Install the reqs
    * Using pip (python3 already installed): `$ pip install -r requirements.txt`
    * Using apt: `$ sudo apt install python3 python3-geoip2 python3-ipwhois python3-requests python3-colorama`
4. Download a copy of the most current MaxMind GeoLite2 City database in mmdb format (learn how to do that here: https://dev.maxmind.com/geoip/geoip2/geolite2/)
5. Download a copy of the log file you want to analyze (see the *Compatible Logs* section below)
6. Run LoggrJack, targeting the downloaded log file and MaxMind database

Alternatively, if you are on a Windows platform, you can download the EXE from the latest release instead of cloning the repo and installing requirements. In this case you would replace `python LoggrJack.py` with `LoggrJack.exe` in all command examples below.

## Compatible Logs

The ultimate goal of the LoggrJack project is to create compatibility with many common text-based log formats, allowing for an at-a-glance review of activity for different systems and applications. LoggrJack is currently able to analyze the following log types:

* Microsoft 365 authentication logs (CSV format export)
* Microsoft IIS logs (W3C default format)

Log types planned for future releases include, but are not limited to:

* Microsoft 365 general event logs
* Azure Active Directory authentication logs
* Debian authentication logs

Commands, tips, and examples are listed in the following section. A short list of FAQs is included after that.

## Commands, Usage Tips, and Examples

![helpimage](https://github.com/TheAirship/LoggrJack/blob/main/Images/LJ%20-%20Help%20(1-3-0).png)

LoggrJack has three analysis modes: Log Summary, Detailed Analysis, and IP Dump. Depending on the size of your environment and the level of user activity, certain analysis configurations may produce a substantial amount of output. Generally, it's advisable to evaluate a week's worth of log data using the Log Summary analysis mode and make adjustments as necessary.

### Log Summary Mode

The Log Summary mode summarizes the data from the log, including top 10 IPv4 addresses, top 10 IPv6 addresses, IP addresses that don't geolocate to the user's current country, and a summary of event data for each user.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s`

You can also modify the top *n* addresses that are included in the summary by passing an integer with the -s parameter. For example, to show only the top 7 IPv4 and IPv6 addresses:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s 7`

To add Have I Been Pwned breach data for each email address found in the log, first obtain your API key from https://haveibeenpwned.com/API/Key, then pass it to LoggrJack using the -p parameter. You can increase the verbosity (-v or -vv) for more detailed breach information.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -s -p [HIBP API Key]`

Some log files include

### Detailed Analysis Mode

The Detailed Analysis mode is LoggrJack's default analysis mode. It creates a line-by-line, chronological listing of events, including date, time, username, source IP, and country data.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file]`

Filtering detailed output is easy. You simply tell LoggrJack what data (i.e. user, IP, or country) you want to filter by and pass a comma-separated list of values along with it. Quoting data passed using the -d parameter is recommended, as shown in the following example. If you can't quote the data list for some reason, you'll need to escape spaces and certain special characters. For example, to filter all results to user *andytaylor@example.com*, use the following:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f user -d "andytaylor@example.com"`

Or, to filter by IP addresses x.x.x.x and y.y.y.y:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f ip -d "x.x.x.x,y.y.y.y"`

You can also exclude specific values from the results using the -x parameter and similar command formatting.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -x country -d "United States,Canada"`

Finally, you can filter or exclude a specific domain if you have multiple domains in your logs. As an example, to only show domains other than example.com:

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -x domain -d "example.com"`

NOTE: You cannot pass both the -f and -x parameters in the same command.

Additional verbosity (-v through -vvv) will return other information, such as more granular event information and the results of a WHOIS lookup for the IP address. Use caution, because higher verbosity levels also means more output. You should consider filtering the full output (e.g. by user, IP, or country) if greater verbosity is desired while using the Detailed Analysis mode.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -f user -d "barneyfife@example.com" -vvv`

### IP Dump Mode

To dump a list of all unique IPv4 and IPv6 addresses found in the log file, use the -i parameter. Increased verbosity (-v or -vv) will add geolocation info to each IP address.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -i`

### Other Command Options

Some logs include events that are benign and only clutter output, such as FaultDomainRedirect in Microsoft 365 logs or HealthMailbox events in IIS. You can filter out these events for a cleaner log analysis with the -g parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -g`

You can also filter RFC 1918 (private), loopback, and APIPA / link local IPv4 and IPv6 addresses from output with the -P parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -P`

By default, LoggrJack uses icanhazip.com to determine a user's public IP address, which is then used to determine the user's current geolocation. If you want to query a different site to determine your public IP, you can use the -M parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -M checkip.amazonaws.com`

Finally, to quick filter down to IPs that geolocate to areas outside of your current country, you can use the -w parameter.

`$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -w`

### FAQ

* How do I get each log type?
    * *Microsoft 365 authentication logs* - Access your Microsoft 365 admin portal and navigate to the 'Audit Log Search' page in the 'Security & Compliance Center'. For this particular log type, be sure to select 'Workspace Analytics > User Logged In' from the 'Activities' selection box. Once the search results are returned, you can click 'Export results' in the upper right side of the window and select 'Download all results'. You can learn more about exporting Microsoft (Office) 365 logs here: https://docs.microsoft.com/en-us/microsoft-365/compliance/export-view-audit-log-records?view=o365-worldwide
    * *Microsoft IIS logs* - IIS logs are located by default in the %SystemDrive%\inetpub\logs\LogFiles directory and may have filenames like 'W3SVC1\ex190411.log' or 'u_ex210220.log'. If this directory is empty or doesn't exist, check the logging configuration in IIS Manager to see if an alternative location was defined. You can learn more about IIS log file configurations here: https://docs.microsoft.com/en-us/iis/configuration/system.applicationhost/sites/sitedefaults/logfile/

* Why were these log types chosen?
    * Because they typically include valuable authentication and event data that could provide insight into, or bring attention, to a security incident. This data isn't always easy to comprehend, and usually does not include geolocation information that can help identify suspicious or unusual activity.

* Can / should I modify log files before I pass them to LoggrJack?
    * LoggrJack expects each logs to be in the default format without any manipulation (e.g., deleted rows, added or removed text). Passing custom log formats will likely result in errors or unexpected results. If you want to omit certain data from log output, use LoggrJack's filter and exclude functions.

* Does LoggrJack require an Internet connection to complete analysis of my logs?
    * In short, no. LoggrJack uses your Internet connection to determine your current country (as part of log analysis), to execute WHOIS lookups, and to pull down data from the Have I Been Pwned API. If you don't want to connect to the Internet, or a connection is unavailable...
        * Do not use verbosity level -vvv with Detailed Analysis mode
        * Do not use the -p parameter to query Have I Been Pwned
        * Manually override the geolocation warning function by passing your current country as an argument with the -w parameter, as shown below:

        `$ python LoggrJack.py -l [path_to_log_file] -m [path_to_MaxMind_mmdb_file] -w "Great Britain"`

* Some of my geolocation results say "unknown city, unknown region". Is that normal?
    * IP geolocation information changes constantly, and it isn't always 100% accurate. Be sure to use the most current MaxMind database available, and understand that you aren't going to get an exact city, region, and country result every time.

* It looks like I'm experiencing repeated attacks from country X. Should I contact their government?
    * Attribution is hard. Just because the source IP of an event geolocates to a specific country doesn't mean that's actually where the event originated. Geolocation information is provided to help spot unusual or suspicious activity, not to catch a bad actor.

* What do I do if I keep get an error or unusual results while using LoggrJack?
    * Log formats may change periodically, and my coding is far from perfect. If you encounter bugs or unexpected results, please submit an issue on GitHub.

* What version of MaxMind's GeoIP products should I use with LoggrJack?
    * LoggrJack was written using the free MaxMind GeoLite2 City database in mmdb format. Other MaxMind GeoLite2 databases and GeoIP products may still work with LoggrJack, especially at lower verbosity levels. GeoLite2 databases in CSV format have not been tested; make sure you download the mmdb format.

* What operating systems / Python versions is LoggrJack compatible with?
    * The LoggrJack Python script can run on many different Linux distros, macOS, and Windows, as long as Python 3 and all necessary dependencies are installed. It was written in Python 3, and tested primarily on 3.9.0. The LoggrJack Windows EXE was tested on Windows 10. NOTE: Use of the Windows EXE does not require Python 3 to be installed.

* Does LoggrJack have a log size limitation?
    * Most likely, but it hasn't been hit in testing. Plus, that limitation is probably more about hardware constraints, and text files tend to be relatively lightweight. For example, on a laptop with a 2.7 GHz Quad-Core i7 proc and 16 GB RAM, LoggrJack completes analysis of a 265,000-line IIS log in <30 seconds, but YMMV.

## About / License

Version and release information can be found in the [Change Log](https://github.com/TheAirship/LoggrJack/blob/main/CHANGELOG.md).

Thanks to [@MaxMind](https://github.com/maxmind) for their excellent work giving locations to IPs.\
Thanks to [@TroyHunt](https://github.com/troyhunt) for his excellent work on Have I Been Pwned?\
Thanks to the many, many people who put time and effort into developing the modules used in LoggrJack.\
\
Questions, comments, and suggestions for improvement are welcome. Contact: infosec@theairship.cloud\
Licensed under [Apache License 2.0](https://github.com/TheAirship/LoggrJack/blob/main/LICENSE)
