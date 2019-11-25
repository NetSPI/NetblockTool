# Netblock Tool
By Alex Poorman

## Purpose
Find netblocks owned by a company

## Usage
```
root@kali:~# python3 NetblockTool.py 
usage:
  _   _      _   _     _            _    _____           _
 | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
 |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
 | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
 |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|

NetblockTool.py [options] {target company}
    Find netblocks owned by a company

Positional arguments:
    {target} Target company (exclude "Inc", "Corp", etc.)

Optional arguments:
    Common Options:
    -l        List mode; argument is a file with list of companies, one per line
    -o        File name to write data to (no extension, default is target name)
    -v        Verbose mode
    -q        Quiet mode
    -h        Print this help message

    Data Retrieval & Processing:
    -n        Don't perform thorough wildcard queries (query = target)
    -w        Perform more thorough complete wildcard queries (query = *target*). Note
                  that this option may return significantly more false positives.
    -c        Company name if different than target (may affect accuracy of confidence
                  scores, use carefully; exclude "Inc", "Corp", etc.)
    -e        Only return results greater than a given confidence score
    -p        Retrieve and write point of contact information to a text file. Note that
                  retrieval of PoC information will likely take some time.
    -4        Only return IPv4 netblocks
    -6        Only return IPv6 netblocks

    Company Subsidiaries:
    -s        Fetch subsidiary information and return netblocks of all subsidiaries in
                  addition to initial target
    -sn       Company name to use when fetching subsidiaries
    -sp       Use alternate parsing method when fetching subsidiary information; use
                  if the default method isn't working as expected
    -so       Write subsidiary information to a text file (CompanyName_subsidiaries.txt)

    Physical Location:
    -g        Retrieve geolocation data (if available)
    -a        Write netblock address information to output
    -ag       Write netblock address information to output but only if it contains a
                  given string

Examples:
    python NetblockTool.py -v Google
    python NetblockTool.py -so -wv Facebook -o Results
    python NetblockTool.py -gavl companies.txt


```
## YouTube Demo
[![Watch the demo](https://i.imgur.com/O37rqG7.png)](https://youtu.be/-UNu8Jp3zvI)

## Recent Changes
* Added deduplication feature
* Added confidence score explanation to output
* Added geolocation functionality
* Added confidence score threshold option
* Added address to output (optional)
* Added address grepping to output (optional)
* Added ARIN URL to output
* Added company subsidiary retrieval feature
* Added support to retrieve netblocks for retrieved subsidiaries
* Added IPv6 support
* Added quiet mode
* Added option to use different name for subsidiary query than netblock query
* Output gathered PoC and address information into a separate file

## General Information
* This script uses both the ARIN API with wildcard queries and ARIN queries through their website search bar, which provides more results than just the wildcard queries alone.
* The confidence score is most effective when the default settings are used. Multiple wildcards and custom company names are supported but generally the best usage will be the default options.

## Imports
Run `pip3 install <module name>` on the following modules:
* netaddr
* bs4
* edgar
* lxml
* requests

Alternatively, you can run `pip3 install -r requirements.txt`

If `pip3` is not in your path, try `C:\Python3\Scripts\pip3.exe install <module name>` or `apt-get install python3-pip`
