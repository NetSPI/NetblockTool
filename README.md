# NetblockTool
Find netblocks owned by a company

[![licence badge]][licence] 
[![stars badge]][stars] 
[![forks badge]][forks] 
[![issues badge]][issues]

[licence badge]:https://img.shields.io/badge/license-New%20BSD-blue.svg
[stars badge]:https://img.shields.io/github/stars/NetSPI/NetblockTool.svg
[forks badge]:https://img.shields.io/github/forks/NetSPI/NetblockTool.svg
[issues badge]:https://img.shields.io/github/issues/NetSPI/NetblockTool.svg

[licence]:https://github.com/NetSPI/NetblockTool/blob/master/LICENSE
[stars]:https://github.com/NetSPI/NetblockTool/stargazers
[forks]:https://github.com/NetSPI/NetblockTool/network
[issues]:https://github.com/NetSPI/NetblockTool/issues


## Overview
* Use NetblockTool to easily dump a unique list of IP addresses belonging to a company and its subsidiaries.
* All data gathering is passive. No traffic is ever sent to the target company.
* Sources include ARIN API, ARIN GUI search functionality, and Google dorking. Company subsidiaries are retrieved from SEC's public database.


## Quick Run
```
git clone https://github.com/NetSPI/NetblockTool.git
cd NetblockTool && pip3 install -r requirements.txt
python3 NetblockTool.py -v Company
```


## Output
Results are written to a CSV called *Company.csv* where *Company* is the provided company's name. The truncated output for Google is shown below.

![NetblockOutput](https://i.imgur.com/XpFNiO0.png) 


## How does this script work?
In depth information on the tool and how it works can be found [here](https://blog.netspi.com/netblocktool/).
* A target company is provided
* Google dorking is used to find netblocks
* Traffic is sent that simulates a user searching ARIN's database for the company name
* All ARIN links are found, visited, and processed from the previous database query
* Duplicate networks are removed
* Each netblock is given a confidence score
* Netblocks are sorted by confidence score and written to a CSV


## Common Use Cases
Simple run. Get results from Google dorking and ARIN database:

`python3 NetblockTool.py Company`

Include the verbose flag to print status updates:

`python3 NetblockTool.py -v Company`

Extract netblocks owned by your target company’s subsidiaries:

`python3 NetblockTool.py -v Company -s`

Extract point of contact information:

`python3 NetblockTool.py -v Company -p`

Get as much information as possible, including netblocks found using wildcard queries, points of contact, geolocation data, and physical addresses:

`python3 NetblockTool.py -wpgav Company -so`


## Help
```
$ ./NetblockTool.py
usage:
  _   _      _   _     _            _    _____           _
 | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
 |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
 | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
 |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|

./NetblockTool.py [options] {target company}
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
    -ng       Don't perform Google Dorking queries
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


### This script isn't working
Ensure the following:
* Are all of the dependencies listed in `requirements.txt` installed?
* Is the `edgar` folder in this repository in the same folder as the NetblockTool.py script?
* Is the script printing out `Google CAPTCHA detected`? You may need to change your public IP or wait ~60 minutes to retrieve Google dorking results. 
* You may need to use Python 3.7+
