# NetblockTool
By Alex Poorman

## Purpose
Find netblocks owned by a company

## Quick Run
```
git clone https://github.com/NetSPI/NetblockTool.git
cd NetblockTool && pip3 install -r requirements.txt
python3 NetblockTool.py -v Company
```

## FAQ
### Why?
Finding netblocks that a company owns is a traditionally very manual process. Tools certainly exist that help with this process but they often simply use the ARIN API, which provides useful information but is ineffective at returning a list of netblocks for a company.

NetblockTool automates the netblock discovery process and uses various sources and techniques to find netblocks, which include the ARIN API, ARIN GUI search functionality, and Google dorking. The netblocks are then processed and assigned a confidence score that they belong to the intended company.

### What is the recommended usage?
Single company:

  * `python3 NetblockTool.py -v Company`
  
Single company & only IPv4 addresses:

  * `python3 NetblockTool.py -v -4 Company`
  
Single company with wildcard queries:

  * `python3 NetblockTool.py -v -w Company`

Multiple companies:

  * `python3 NetblockTool.py -v -l company_list.txt`

### What data does this need?
This script only needs the target company name. It is useful, however, to try both normal and wildcard queries to see if additional results are provided with the wildcard query.

### How does this script work?
* A target company is provided
* Google dorking is used to find netblocks
* Traffic is sent that simulates a user searching ARIN's database for the company name
* All ARIN links are found, visited, and processed from the previous database query
* Duplicate networks are removed
* Each netblock is given a confidence score
* Netblocks are sorted by confidence score and written to a CSV

### This script isn't working
Ensure the following:
* Are all of the dependencies listed in `requirements.txt` installed?
* Is the version of the installed `edgar` dependency 1.0.0?
* Is the script printing out `Google CAPTCHA detected`? You may need to change your public IP or wait ~60 minutes to retrieve Google dorking results. 

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

## Dependencies
Run `pip3 install <module name>` on the following modules:
* netaddr
* bs4
* edgar
* lxml
* requests

Alternatively, you can run `pip3 install -r requirements.txt`
