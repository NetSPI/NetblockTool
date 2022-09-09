#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#------------------------------------------------------------------------------#
#  _   _      _   _     _            _    _____           _                    #
# | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |                   #
# |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |                   #
# | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |                   #
# |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|                   #
#                                                                              #
# Name:        Netblock Tool (NetblockTool.py)                                 #
# Purpose:     Find netblocks owned by a given company                         #
#                                                                              #
# Author:      Alex Poorman                                                    #
# Sponsor:     NetSPI (https://netspi.com)                                     #
#------------------------------------------------------------------------------#


# Modules & Imports
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import sys
import re
import json
import csv
import operator
import argparse
import urllib
import socket
import netaddr
import edgar
import requests
import time
import random
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from lxml import html
from bs4 import BeautifulSoup


# Configure requests to only support high-level ciphers
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += 'HIGH:!DH:!aNULL'


# Program details
__authors__ = ['Alex Poorman', 'NetSPI']
__version__ = '2.0.0'

# Global variables
STATES = ['afghanistan', 'ak', 'al', 'alabama', 'alaska', 'albania', 'alberta',
          'algeria', 'american samoa', 'andorra', 'angola', 'antigua & deps',
          'ar', 'argentina', 'arizona', 'arkansas', 'armenia', 'as',
          'australia', 'austria', 'az', 'azerbaijan', 'bahamas', 'bahrain',
          'bangladesh', 'barbados', 'belarus', 'belgium', 'belize', 'benin',
          'bermuda', 'bhutan', 'bolivia', 'bosnia herzegovina', 'botswana',
          'brazil', 'british columbia', 'brunei', 'bulgaria', 'burkina',
          'burma', 'burundi', 'ca', 'california', 'cambodia', 'cameroon',
          'canada', 'cape verde', 'cayman islands', 'central african rep',
          'chad', 'chile', 'china', 'co', 'colombia', 'colorado', 'comoros',
          'congo', 'connecticut', 'costa rica', 'croatia', 'ct', 'cuba',
          'cyprus', 'czech republic', 'dc', 'de', 'delaware', 'delaware usa',
          'democratic republic of the congo', 'denmark', 'district of columbia',
          'djibouti', 'dominica', 'dominican republic', 'east timor', 'ecuador',
          'egypt', 'el salvador', 'england', 'england and wales',
          'equatorial guinea', 'eritrea', 'espana', 'estonia', 'ethiopia',
          'federated states of micronesia', 'fiji', 'finland', 'fl', 'florida',
          'fm', 'france', 'ga', 'gabon', 'gambia', 'georgia', 'georgia',
          'germany', 'ghana', 'greece', 'grenada', 'gu', 'guam', 'guatemala',
          'guinea', 'guinea-bissau', 'guyana', 'haiti', 'hawaii', 'hi',
          'honduras', 'hong kong', 'hungary', 'ia', 'iceland', 'id', 'idaho',
          'il', 'illinois', 'in', 'india', 'indiana', 'indonesia', 'iowa',
          'iran', 'iraq', 'ireland', 'israel', 'italy', 'ivory coast',
          'jamaica', 'japan', 'jordan', 'kansas', 'kazakhstan', 'kentucky',
          'kenya', 'kiribati', 'korea', 'korea north', 'korea republic of',
          'korea south', 'kosovo', 'ks', 'kuwait', 'ky', 'kyrgyzstan', 'la',
          'laos', 'latvia', 'lebanon', 'lesotho', 'liberia', 'libya',
          'liechtenstein', 'lithuania', 'louisiana', 'luxembourg', 'ma',
          'macedonia', 'madagascar', 'maine', 'malawi', 'malaysia', 'maldives',
          'mali', 'malta', 'manitoba', 'marshall islands', 'marshall islands',
          'maryland', 'massachusetts', 'mauritania', 'mauritius', 'md', 'me',
          'mexico', 'méxico', 'mh', 'mi', 'michigan', 'micronesia', 'minnesota',
          'mississippi', 'missouri', 'mn', 'mo', 'moldova', 'monaco',
          'mongolia', 'montana', 'montenegro', 'morocco', 'mozambique',
          'mp', 'ms', 'mt', 'myanmar', 'namibia', 'nauru', 'nc', 'nd', 'ne',
          'nebraska', 'nederland', 'nepal', 'netherlands', 'nevada',
          'new brunswick', 'new hampshire', 'new jersey', 'new mexico',
          'new york', 'new zealand', 'newfoundland and labrador', 'nh',
          'nicaragua', 'niger', 'nigeria', 'nj', 'nm', 'north carolina',
          'north dakota', 'north ireland', 'northern mariana islands', 'norway',
          'nova scotia', 'nv', 'ny', 'of', 'oh', 'ohio', 'ok', 'oklahoma',
          'oman', 'ontario', 'or', 'oregon', 'pa', 'pakistan', 'palau',
          'panama', 'papua new guinea', 'paraguay', 'pennsylvania', 'peru',
          'philippines', 'poland', 'portugal', 'pr', 'prince edward island',
          'puerto rico', 'pw', 'qatar', 'quebec', 'republic of ireland',
          'republic of korea', 'rhode island', 'ri', 'romania', 'russia',
          'russia/kazakhstan', 'russian federation', 'rwanda',
          'saint vincent & the grenadines', 'samoa', 'san marino',
          'sao tome & principe', 'saskatchewan', 'saudi arabia', 'sc', 'sd',
          'senegal', 'serbia', 'seychelles', 'sierra leone', 'singapore',
          'slovakia', 'slovenia', 'solomon islands', 'somalia', 'south africa',
          'south carolina', 'south dakota', 'south korea', 'south sudan',
          'spain', 'sri lanka', 'st kitts & nevis', 'st lucia', 'sudan',
          'suriname', 'swaziland', 'sweden', 'switzerland', 'syria', 'taiwan',
          'taiwan', 'taiwan province of china', 'tajikistan', 'tanzania',
          'tennessee', 'texas', 'thailand', 'the bahamas & eleuthera island',
          'tn', 'togo', 'tonga', 'trinidad & tobago', 'tunisia', 'turkey',
          'turkmenistan', 'tuvalu', 'tx', 'uganda', 'uk', 'ukraine',
          'united arab emirates', 'united kingdom', 'united states', 'uruguay',
          'us', 'usaunited kingdom & northern ireland', 'ut', 'utah',
          'uzbekistan', 'va', 'vanuatu', 'vatican city', 'venezuela', 'vermont',
          'vietnam', 'virgin islands', 'virginia', 'vt', 'wa', 'washington',
          'west virginia', 'wi', 'wisconsin', 'wv', 'wy', 'wyoming', 'yemen',
          'zambia', 'zimbabwe','people\'s republic of china', 'isle of man',
          'the netherlands', 'serbia & montenegro', 'serbia and montenegro',
          'british virgin islands', 'bosnia & herzogovina',
          'bosnia and herzogovina']
EXT = ['llc', 'corp', 'corporation', 'inc', 'ltd', 'limited', '-cust', 'lp',
       'jv', 'pc', 'llp', 'lllp', 'pllc', 'dba', 'cust', 'co', 'company',
       'gmbh', 'ulc', 'sas', 'kk', 'bv', 'sl', 'sa de cv', 's de rl de cv',
       'bvba', 'limitada', 'gk', 'ua', 'lda', 'sl unipersonal', 'sdn bhd',
       'bhd', 'sp z oo', 'as', 'ab', 'lilc', 'sro', 'sà rl', 'srl', 'sro', 'cv',
       'plc', 'sàrl', 'sarl', 'ag', 'sa', 'scs', 'nv', 'companies',
       'incorporated', 'pte', 'aps', 'pty', 'aeie', 'snc', 'sp zoo', 'fzco',
       'dwc-llc', 'ltda', 'group', 'of', 'private']
USER_AGENT = 'CompanyName Name email@companyname.com'


def main(passed_target, passed_company_name, passed_query, passed_verbose,
         passed_threshold, passed_geo, passed_address, passed_address_grep,
         passed_version, passed_quiet, passed_poc, passed_no_google):
    # Process arguments
    target = passed_target
    query = passed_query
    if not passed_company_name:
        company_name = target
    else:
        company_name = passed_company_name
    if passed_threshold:
        threshold = int(passed_threshold)
    else:
        threshold = passed_threshold
    verbose = passed_verbose
    quiet = passed_quiet
    geolocation = passed_geo
    address_out = passed_address
    address_grep = passed_address_grep
    ip_version = passed_version
    query_poc = passed_poc
    no_google = passed_no_google
    return_list = []

    # Function variables
    csv_headers = ['Network', 'Name', 'ID', 'Type', 'Confidence',
                   'Score Rationale', 'Resource URL']
    arin_org_addresses = []
    arin_net = []
    arin_asn = []
    arin_pocs = []
    arin_customer = []
    process_list = []
    write_list = []
    address_freq = []
    retrieved_pocs = []
    arin_pocs_unique = []
    google_networks = []
    arin_object_count = 0
    attempts = 20

    # Get networks from Google
    if not no_google:
        if not quiet:
            print('[*] Retrieving networks using Google Dorking for', target,'(usually < 30 pages)')
        google_networks = get_google_networks(target, verbose, quiet)
        if google_networks:
            for net in google_networks:
                arin_net.append(net)
        elif google_networks == False:
            if not quiet:
                print('  [!] Google CAPTCHA detected. Unable to retrieve results from Google.')
        else:
            if not quiet:
                print('[!] No networks found using Google for '+target)

    # Get ARIN objects
    if not quiet:
        print('[*] Retrieving ARIN objects using keyword', query)
    arin_objects = get_arin_objects(query)
    if arin_objects:
        if not quiet:
            print('[*] Processing '+str(len(arin_objects))+' retrieved ARIN objects')
        if (not verbose and not quiet):
            print('[*] This may take a few minutes, depending on the target')
        for item in arin_objects:
            arin_object_count += 1
            if verbose:
                print('  ['+str(arin_object_count)+'/'+str(len(arin_objects))+']', item, ' '*50, end='\r')
            if '/rest/net' in item and not item.endswith('/rdns'):
                if not item.endswith('/resources'):
                    if not item.endswith('/pocs'):
                        success = False
                        for attempt in range(1, attempts+1):
                            try:
                                initial_net = get_net_info(item)
                                for net in initial_net:
                                    arin_net.append(net)
                                success = True
                                break
                            except requests.exceptions.RequestException:
                                None
                        if not success:
                            print('  [!] Unable to retrieve details for ' + item, ' ' * 20)
            elif '/rest/asn' in item and not item.endswith('/pocs'):
                success = False
                for attempt in range(1, attempts+1):
                    try:
                        initial_asn = get_asn_info(item)
                        for net in initial_asn:
                            arin_asn.append(net)
                        success = True
                        break
                    except requests.exceptions.RequestException:
                        None
                if not success:
                    print('  [!] Unable to retrieve details for ' + item, ' ' * 20)
            elif '/rest/customer' in item:
                success = False
                for attempt in range(1, attempts+1):
                    try:
                        return_cust = get_customer_info(item)
                        arin_net.append(return_cust)
                        arin_customer.append(return_cust)
                        success = True
                        break
                    except requests.exceptions.RequestException:
                        None
                if not success:
                    print('  [!] Unable to retrieve details for ' + item, ' ' * 20)
            elif '/rest/org' in item and not item.endswith('/pocs'):
                success = False
                for attempt in range(1, attempts+1):
                    try:
                        arin_org_addresses.append(get_org_address_info(item))
                        if query_poc:
                            for contact in get_org_poc_info(item):
                                arin_pocs.append(contact)
                        success = True
                        break
                    except requests.exceptions.RequestException:
                        None
                if not success:
                    print('  [!] Unable to retrieve details for ' + item, ' ' * 20)
            if query_poc:
                if '/rest/poc/' in item:
                    if item not in retrieved_pocs:
                        success = False
                        for attempt in range(1, attempts+1):
                            try:
                                arin_pocs.append(get_poc_info(item))
                                retrieved_pocs.append(item)
                                success = True
                                break
                            except requests.exceptions.RequestException:
                                None
                        if not success:
                            print('  [!] Unable to retrieve details for ' + item, ' ' * 20)

    if (arin_objects) or (google_networks):
        # If PoC info was requested, deduplicate, sort, and write to file
        if query_poc:
            process_poc_output(arin_pocs, target, verbose, quiet)

        # TODO: Use gathered address information from POC info to score addresses

        # Process data for confidence scoring
        # Object output: [Network, Name, ARIN_Handle, Address, Type, ARIN_URL]
        arin_asn = sorted(arin_asn, key=operator.itemgetter(0))
        arin_customer = sorted(arin_customer, key=operator.itemgetter(0))
        arin_net = sorted(arin_net, key=operator.itemgetter(0))
        process_list = arin_customer + arin_net + arin_asn
        process_list = process_dedup_filter(process_list, ip_version)
        address_freq = process_addresses(arin_org_addresses)

        # Process netblock confidence
        write_list = process_netblock_confidence(process_list, company_name, query, address_freq)

        # Sort data based on confidence score
        write_list = sorted(write_list, key=operator.itemgetter(4), reverse=True)

        # Remove duplicate ranges
        write_list = process_duplicate_ranges(write_list, verbose, quiet)

        # Manipulate output data based on arguments
        if threshold:
            write_list = process_confidence_threshold(write_list, threshold)
        if address_out:
            csv_headers.append('Registered Address')
        write_list = process_output_addresses(write_list, address_out, address_grep)
        if geolocation:
            csv_headers.append('Geolocation Information')
            write_list = process_geolocation(write_list, verbose, quiet)

        # Return data
        return_list.append(write_list)
        return_list.append(csv_headers)
        return return_list
    else:
        # If no ARIN objects were found, return a blank list
        print('[!] No ARIN objects were found using query '+query)
        return []


def process_netblock_confidence(process_list, company_name, query, address_freq):
    """Assign a confidence score for each discovered netblock.

    Args:
        process_list: A list of netblocks with identifying information.
        company_name: The name of the company to use for confidence scoring.
        query: The query used when searching the ARIN database.
        address_freq: A list containing discovered addresses and what percentage
            each address represents out of all addresses.

    Returns:
        A modified process_list that removes address information and adds a
        confidence score.
    """
    return_list = []
    company_strings = [company_name]
    for ext in EXT:
        company_strings.append(company_name+' '+ext)
    for sub_list in process_list:
        reason = ''
        found = False
        score = 0
        # Get address value and then remove
        address = sub_list[3]
        del sub_list[3]
        # Baseline score from source
        if sub_list[3] == 'asn':
            score += 65
            reason = 'ASN'
        elif sub_list[3] == 'customer':
            score += 70
            reason = 'Customer'
        elif sub_list[3] == 'network':
            score += 50
            reason = 'Network'
        # Company name
        check_string = process_company_name(''.join(sub_list[1]).lower(), company_name)
        if company_name.lower() not in check_string.lower():
            score -= 50
            reason += ', company name not in name parameter'
        for name_check in company_strings:
            if name_check.lower() == check_string.lower():
                reason += ', company name is name parameter'
                if sub_list[3] == 'customer':
                    score += 15
                else:
                    score += 20
                found = True
        if not found:
            for name_check in company_strings:
                try:
                    if name_check.lower() == check_string:
                        score += 10
                        reason += ', company name in name parameter'
                        found = True
                except IndexError:
                    None
        # Remove data after '-' and perform check again
        hyphen_check_string = ''.join(sub_list[1]).lower().replace(',','').replace('.','')
        if not found:
            for i in hyphen_check_string:
                if i.isdigit():
                    hyphen_check_string = hyphen_check_string.split(i)[0]
                    if len(hyphen_check_string) > 0:
                        if hyphen_check_string[-1] == '-':
                            hyphen_check_string = hyphen_check_string[:-1]
            for name_check in company_strings:
                if name_check.lower() == hyphen_check_string.lower():
                    score += 10
                    reason += ', company name is name parameter'
                    found = True
        # Check if company_name+extension is in handle
        if not found:
            for name_check in company_strings:
                if name_check.lower() != company_name.lower():
                    if name_check.lower() in check_string.lower():
                        found = True
        # If not found, lower score
        if not found:
            if sub_list[3] == 'customer':
                score -= 25
                reason += ', no company name and extension match'
            if sub_list[3] == 'network':
                score -= 20
                reason += ', no company name and extension match'
        # a-z after company name lowers score
        if company_name.lower() in str(sub_list[1]).lower():
            try:
                if str(check_string.lower().split(company_name.lower())[1])[0].isalpha() == True:
                    if not found:
                        score -= 10
                        reason += ', alphabetic characters after company name'
            except IndexError:
                None
        # If both wildcards used, a-z before company name lowers score
        if query[0] == '*':
            if company_name.lower() in str(sub_list[1]).lower():
                try:
                    if str(check_string.lower().split(company_name.lower())[0])[-1].isalpha() == True:
                        if not found:
                            score -= 10
                            reason += ', both wildcards used in query & alphabetic characters after company name'
                except IndexError:
                    None
        # Address scoring
        for test_addr in address_freq:
            if address == test_addr[1]:
                num = int(round(75*test_addr[0]))
                if score >= 50:
                    reason += ', address match from ARIN objects'
                    if num > 15:
                        num = 15
                else:
                    score += 22
                    reason += ', address match from ARIN objects (significant score increase)'
                score += num
        # If no IP, score = 0
        try:
            netaddr.IPNetwork(sub_list[0])
        except netaddr.AddrFormatError:
            score = 0
            reason = 'No IP information'
        # Process final scoring
        if score < 0:
            score = 0
            reason += ', score adjusted to 0 to keep within threshold'
        elif score >= 99:
            score = 99
            reason += ', score adjusted to 99 to keep within threshold'
        # Process for final writing
        arin_link = sub_list[4]
        del sub_list[4]
        sub_list.append(score)
        sub_list.append(reason)
        sub_list.append(arin_link)
        sub_list.append(address)
        return_list.append(sub_list)
    return return_list


def process_addresses(address_list):
    """Determines how frequent each address appears out of all addresses found.

    Args:
        address_list: A list of organization information with addresses
            that was retrieved from ARIN.

    Returns:
        A list of lists, with the sub list containing two elements. Element one
        is a the frequency that the address appears and element two is the
        address. For example:

        [
         [0.75, '123 APPLE WAY, ANYTOWN, United States, 12345'],
         [0.25, '123 MAIN STREET, SPRINGFIELD, United States, 54321']
        ]
    """
    results = []
    for item in set(address_list):
        temp = []
        num = int(address_list.count(item))
        temp.append(num/float(len(address_list)))
        temp.append(item)
        results.append(temp)
    results = sorted(results, key=operator.itemgetter(0), reverse=True)
    return results


def process_company_name(potential_name, company_name):
    """Remove bad characters from potential company names.

    Args:
        potential_name: The retrieved potential company name to remove bad
            characters from.
        company_name: The name of the company.

    Returns:
        A modified potential_name string that contains no bad characters.
    """
    returnName = potential_name.replace(',', '')
    if '.' not in company_name:
        returnName = returnName.replace('.', '')
    if '-' not in company_name:
        returnName = returnName.replace('-', ' ')
    return returnName


def process_dedup_filter(netblock_list, version):
    """Filter out duplicate networks based on ARIN handle and unrequested IP
       version netblocks.

    Args:
        netblock_list: A list of netblocks with identifying information.
        version: Requested IP version (4, 6, or None for 4 & 6).

    Returns:
        A modified netblock_list that removes duplicates and unrequested IP
        version netblocks.
    """
    process_list = []
    return_list = []
    dups = []
    # Remove duplicates except for ASN
    for item in netblock_list:
        if item[4] != 'asn':
            if item[2] not in dups:
                process_list.append(item)
            dups.append(item[2])
        else:
            process_list.append(item)
    # Remove netblocks if based on specified IP version
    for sub_list in process_list:
        try:
            sub_list[0] = netaddr.IPNetwork(sub_list[0])
        except netaddr.AddrFormatError:
            None
    for sub_list in process_list:
        if version:
            try:
                if sub_list[0].version == version:
                    sub_list[0] = str(sub_list[0])
                    return_list.append(sub_list)
            except AttributeError:
                sub_list[0] = str(sub_list[0])
                return_list.append(sub_list)
        else:
            sub_list[0] = str(sub_list[0])
            return_list.append(sub_list)
    return return_list


def process_ip_count(netblock_list, version):
    """Return number of IPs that were retrieved by the tool.

    Args:
        netblock_list: A list of netblocks with identifying information.
        version: Requested IP version (4 or 6).
    """
    potential_nets = []
    nets = []
    ipNum = 0
    for sub_list in netblock_list:
        if sub_list[4] != 0:
            potential_nets.append(sub_list[0])
    for net in potential_nets:
        try:
            nets.append(netaddr.IPNetwork(net))
        except netaddr.AddrFormatError:
            None
    for net in nets:
        if net.version == version:
            ipNum += net.size
    return ipNum


def process_url_encode(encode_string):
    """URL encodes a string.
    """
    return urllib.parse.quote_plus(encode_string)


def process_output_name(encode_string):
    """Removes all bad characters in a string so it can be used as a file name.
    """
    return_string = re.sub('[^\w\-_\. ]', '_', encode_string)
    return_string = return_string.replace(' ', '_')
    return return_string


def process_duplicate_ranges(netblock_list, verbose, quiet):
    """Removes duplicate IP ranges.

    Args:
        netblock_list: A list of netblocks with identifying information.
        verbose: A boolean that indicates whether verbose status messages
            should be printed.
        quiet: A boolean that indicates that all status messages should be
            disabled.

    Returns:
        A modified netblock_list that changes the confidence score of the lowest
        duplicate range to 0 and that is sorted by the confidence score in
        descending order.
    """
    #Local variables
    basic_ranges = []
    ranges = []
    ranges6 = []
    blacklist = []
    blacklist6 = []
    return_list = []
    final_return_list = []
    no_ip_data = []
    range_status = 0
    removed = 0

    # Advanced check (is small range within larger range)
    if quiet == False:
        print('\n[*] Removing duplicate ranges')
    ## Get IPv4 addresses
    for sub_list in netblock_list:
        try:
            netaddr.IPNetwork(sub_list[0])
            if netaddr.IPAddress(sub_list[0].split('/')[0]).version == 4:
                if sub_list[4] != 0:
                    ranges.append(sub_list[0])
            elif netaddr.IPAddress(sub_list[0].split('/')[0]).version == 6:
                if sub_list[4] != 0:
                    ranges6.append(sub_list[0])
            else:
                no_ip_data.append(sub_list)
        except netaddr.AddrFormatError:
            no_ip_data.append(sub_list)
    ranges.sort(reverse=False, key=lambda network: socket.inet_aton(network.split('/')[1]))
    ranges6.sort(key=lambda network: int(network.split('/')[1]))
    ## Find IPv4 duplicates
    for network1 in ranges:
        range_status += 1
        if verbose:
            if range_status % 50 == 0:
                if not quiet:
                    print('  [*] Status: '+str(range_status)+'/'+str(len(ranges)+len(ranges6)), ' '*20, end='\r')
            elif (range_status == len(ranges)+len(ranges6) and len(ranges6) == 0):
                if not quiet:
                    print('  [*] Status: '+str(range_status)+'/'+str(len(ranges)+len(ranges6)), ' '*20, end='\r')
        for network2 in ranges:
            if network1 != network2:
                if netaddr.IPNetwork(network1) in netaddr.IPNetwork(network2):
                    blacklist.append(network1)
    ## Find IPv6 duplicates
    for network1 in ranges6:
        range_status += 1
        if verbose:
            if range_status % 50 == 0:
                if quiet == False:
                    print('  [*] Status: '+str(range_status)+'/'+str(len(ranges)+len(ranges6)), ' '*20, end='\r')
            elif range_status == len(ranges)+len(ranges6):
                if not quiet:
                    print('  [*] Status: '+str(range_status)+'/'+str(len(ranges)+len(ranges6)), ' '*20, end='\r')
        for network2 in ranges6:
            if network1 != network2:
                if netaddr.IPNetwork(network1) in netaddr.IPNetwork(network2):
                    blacklist6.append(network1)
    ## Mark all duplicates
    for sub_list in netblock_list:
        try:
            netaddr.IPNetwork(sub_list[0])
            if netaddr.IPAddress(sub_list[0].split('/')[0]).version == 4:
                if sub_list[0] in blacklist:
                    sub_list[4] = 0
                    sub_list[5] = 'Duplicate network'
                    return_list.append(sub_list)
                    removed += 1
                else:
                    return_list.append(sub_list)
            elif netaddr.IPAddress(sub_list[0].split('/')[0]).version == 6:
                if sub_list[0] in blacklist6:
                    sub_list[4] = 0
                    sub_list[5] = 'Duplicate network'
                    return_list.append(sub_list)
                    removed += 1
                else:
                    return_list.append(sub_list)
        except netaddr.AddrFormatError:
            None

    # Basic check (is range equal to another range)
    return_list = sorted(return_list, key=operator.itemgetter(4), reverse=True)
    for sub_list in return_list:
        if sub_list[0] not in basic_ranges:
            basic_ranges.append(sub_list[0])
            final_return_list.append(sub_list)
        else:
            # Modify confidence score and reason if duplicate
            sub_list[4] = 0
            sub_list[5] = 'Duplicate network'
            final_return_list.append(sub_list)
            removed += 1

    # Process data and return
    if not quiet:
        print('  [*] Marked '+str(removed)+' ranges as duplicate')
    for sub_list in no_ip_data:
        final_return_list.append(sub_list)
    final_return_list = sorted(final_return_list, key=operator.itemgetter(4), reverse=True)
    return final_return_list


def process_confidence_threshold(netblock_list, threshold):
    """Returns results that are greater than given threshold.

    Args:
        netblock_list: A list of netblocks with identifying information.
        threshold: The threshold at which confidence scores lower than
            this number should be excluded.

    Returns:
        A modified netblock_list that excludes all netblocks with a confidence
        score less than the threshold.
    """
    return_list = []
    for sub_list in netblock_list:
        if sub_list[4] >= threshold:
            return_list.append(sub_list)
    return return_list


def process_output_addresses(netblock_list, address_out, passed_address_grep):
    """Prepares address information for output based on the user's preferences.

    Args:
        netblock_list: A list of netblocks with identifying information.
        address_out: A boolean indicating whether the addresses will be
            written to the netblock output file.
        passed_address_grep: The string to look for in each address. If found,
            the netblock will be returned. If not, it will be discarded.

    Return:
        Returns a modified netblock_list that either contains address data,
        filtered or not depending on the user's arguments, or has address data
        removed.
    """
    return_list = []
    if address_out:
        if len(passed_address_grep) > 0:
            for sub_list in netblock_list:
                if passed_address_grep in str(sub_list[7]).lower():
                    return_list.append(sub_list)
                else:
                    del sub_list[7]
                    return_list.append(sub_list)
            return return_list
        else:
            return netblock_list
    else:
        for sub_list in netblock_list:
            del sub_list[7]
            return_list.append(sub_list)
        return return_list


def process_geolocation(netblock_list, verbose, quiet):
    """Processes and retrieves geolocation data.

    Args:
        netblock_list: A list of netblocks with identifying information.
        verbose: A boolean that indicates whether verbose status messages
            should be printed.
        quiet: A boolean that indicates that all status messages should be
            disabled.

    Returns:
        Returns a modified netblock_list that contains an additional entry with
        geolocation data (if available) for each netblock.
    """
    return_list = []
    status = 0
    if not quiet:
        print('\n[*] Retrieving geolocation data')
    for sub_list in netblock_list:
        status += 1
        if verbose:
            if status % 25 == 0:
                if not quiet:
                    print('  [*] Status: '+str(status)+'/'+str(len(netblock_list)))
            elif status == len(netblock_list):
                if quiet == False:
                    print('  [*] Status: '+str(status)+'/'+str(len(netblock_list)))
        sub_list.append(get_ip_coordinates(sub_list[0]))
        return_list.append(sub_list)
    return return_list


def process_potential_company(test_string, company_name):
    """Determines if a given string is likely a company name.

    Args:
        test_string: The string to test.
        company_name: The official company name that was retrieved from the
            SEC EDGAR database.

    Returns:
        Returns the filtered test_string if is is determined to be a company
        name. If it is not, None will be returned.
    """
    # Local objects
    blacklist = ['exhibit 21.1', 'ex-21.1', 'ex-2101', 'jurisdiction', 'legal name',
                 'exhibit 21', 'registrant', 'percent owned', 'exhibit 2101', 'subsidiar',
                 'percentage of', 'entity name', 'voting securities', 'owned directly',
                 'state or sovereign power of incorporation', 'company name',
                 'ownership %', 'state or', 'provinceof', 'rule 1-02', 'of organization',
                 'owneddirectly', 'percentageof', 'stateor', 'orindirectly by',
                 'of incorporation', 'or organization', 'item 601', 'reg s-k', 'no fear act',
                 'directory listing', 'click here']
    blacklist_equal = ['site map', 'contact', 'links', 'careers', 'plain writing',
                       'contracts', 'organization', 'incorporation', 'education',
                       'open government', 'enforcement', 'notes:', 'names under which', 'usa.gov',
                       'about', 'and', 'foia', 'inspector general', 'news', 'investor.gov',
                       'accessibility', 'name of company', 'regulation', 'filings', 'divisions',
                       'privacy', 'what\'s new', 'what we do', 'webcasts', 'upcoming events']
    date = ['january', 'february', 'march', 'april', 'june', 'july', 'august', 'september',
            'october', 'november', 'december']

    # Company filter logic
    ## Standardize input string
    temp = test_string.rstrip()
    temp = temp.replace('  ', '')
    temp = temp.replace('\n', '')
    temp = temp.replace(u'\xa0', u' ')
    temp = temp.replace(',', '')
    ## Test if not link to webpage
    if '.htm' not in temp:
        ## Test if blacklisted word/phrase is not in string
        if temp.lower() not in blacklist:
            for phrase in blacklist:
                if phrase in temp.lower():
                    return None
            for phrase in blacklist_equal:
                if phrase == temp.lower():
                    return None
            temp = temp.replace('.', '')
            if len(temp) > 1:
                ## Test if not an integer
                try:
                    int(''.join(e for e in temp if e.isalnum()))
                except ValueError:
                    ## Test if not only state/country name
                    if temp.lower() not in STATES:
                        for state in STATES:
                            if ''.join(e for e in state if e.isalnum()) == ''.join(e for e in temp.lower() if e.isalnum()):
                                return None
                        if temp.replace(' ', '').lower() not in company_name.replace(' ', '').lower():
                            ## Test if string is likely a date
                            for month in date:
                                if month in temp.lower():
                                    dateTemp = temp.lower().split(month)[1]
                                    dateTemp = ''.join(e for e in dateTemp if e.isalnum())
                                    if dateTemp.isalnum():
                                        return None
                            ## Check if overly long or short
                            if len(temp) < 100:
                                if len(temp) > 5:
                                    ## Check if only special characters
                                    if re.match('^[\W_]+$', temp.lower()):
                                        return None
                                    ## Remove data within parentheses, if applicable
                                    if ('(') and (')') in temp.lower():
                                        temp = temp.split('(')[0]+temp.split(')')[1]
                                        temp = temp.replace('  ', ' ')
                                        if len(temp) > 0:
                                            if re.match('^[a-zA-Z]*', temp):
                                                return temp
                                    else:
                                        return temp


def process_company_extension(company_list):
    """Removes company extensions.

    Args:
        company_list: A list of company names that were retrieved from the
            SEC EDGAR database.

    Returns:
        A modified company_list that contains a company name without an
        extension (e.g.: "LLC") or a state (e.g.: "United States").
    """
    # Local objects
    process_list = []
    return_list = []
    # Logic to remove company extension
    for company in company_list:
        found = False
        if company.lower().rstrip().startswith('the '):
            company = company[4:]
        for ext in EXT:
            if company.lower().rstrip().endswith(' '+ext):
                found = True
                company = company.lower().replace(ext, '')
                company = company.replace(' ', ' ')
                company = company.rstrip()
                if re.match('^[\W_]+$', company[-1]):
                    company = company[:-1]
                company = company.title().rstrip()
        process_list.append(company.rstrip())
    # Remove state if the last word is a state
    for company in process_list:
        # Recursive removal
        for x in range(0, 3):
            for state in STATES:
                if company.lower().endswith(' '+state):
                    company = company.lower().replace(' '+state, '')
                    company = company.title().rstrip()
        return_list.append(company)
    return sorted(set(return_list))


def process_output_file(netblock_list, output_file_name, header_list):
    """Write the finalized netblocks to a CSV file.

    Args:
        netblock_list: A list of netblocks with identifying information.
        output_file_name: The filename to write the results to.
        header_list: A list containing the name of the CSV headers for each
            item in the netblock_list.
    """
    # Write data
    if netblock_list:
        try:
            with open(output_file_name, 'w', newline='') as output_file:
                writer = csv.writer(output_file, delimiter=',')
                writer.writerow(header_list)
                for sub_list in netblock_list:
                    writer.writerow(sub_list)
            print('\n[*] Data written to', output_file_name)
        except IOError:
            print('\n[!] WARNING: Error with filename', output_file_name)
            ## TODO: replace input() so that no user input is ever required
            output = str(input('[+] Please enter a new filename (no extension): '))
            if output:
                output = 'output'
            output = process_output_name(output)
            output += '.csv'
            with open(output, 'w', newline='') as output_file:
                writer = csv.writer(output_file, delimiter=',')
                writer.writerow(header_list)
                for sub_list in netblock_list:
                    writer.writerow(sub_list)
            print('\n[*] Data written to', output)


def process_poc_output(poc_list, target, verbose, quiet):
    """Write the finalized netblocks to a CSV file.

    Args:
        poc_list: A list of point of contact information from ARIN.
        target: The company the PoC information was gathered for.
        verbose: A boolean that indicates whether verbose status messages
            should be printed.
        quiet: A boolean that indicates that all status messages should be
            disabled.
    """
    poc_list_unique = []
    poc_list = sorted(set(tuple(item) for item in poc_list))
    for contact in poc_list:
        poc_list_unique.append(list(contact))
    if poc_list_unique:
        try:
            with open(process_output_name(target)+'_contacts.csv', 'w') as output_file:
                writer = csv.writer(output_file, delimiter=',', lineterminator='\n')
                writer.writerow(['Name', 'Company', 'Address', 'Emails', 'Phone Numbers'])
                for contact in poc_list_unique:
                    writer.writerow(contact)
            print('\n[*] Point of contact data written to',
                  process_output_name(target)+'_contacts.csv')
        except IOError:
            print('\n[!] WARNING: Error with filename',
                  process_output_name(target)+'_contacts.csv')
            ## TODO: replace input() so that no user input is ever required
            output = str(input('[+] Please enter a new filename (no extension): '))
            if output:
                output = 'retrieved_contacts'
            output = process_output_name(output)
            output += '.csv'
            with open(output, 'w', newline='') as output_file:
                writer = csv.writer(output_file, delimiter=',', lineterminator='\n')
                writer.writerow(['Name', 'Company', 'Address', 'Emails', 'Phone Numbers'])
                for contact in poc_list_unique:
                    writer.writerow(contact)
            print('\n[*] Point of contact data written to', output)


def get_arin_objects(target_name):
    """Search ARIN for target matches using the search bar.

    Args:
        target_name: The name of the target.

    Returns:
        Returns a list of ARIN REST API resource URLs.
    """
    return_list = []
    blacklist = ['.html']
    data = 'flushCache=true&queryinput='+process_url_encode(target_name)+'&whoisSubmitButton=+'
    headers = {'Host'          :   'whois.arin.net',
               'User-Agent'    :   'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:61.0) Gecko/20100101 Firefox/61.0',
               'Accept'        :   'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language':  'en-US,en;q=0.5',
               'Accept-Encoding':  'gzip, deflate',
               'Referer'       :   'https://whois.arin.net/ui/query.do',
               'Content-Type'  :   'application/x-www-form-urlencoded',
               'Content-Length':   str(len(data)),
               'Connection'    :   'close'}
    req = requests.post('https://whois.arin.net/ui/query.do', data=data, headers=headers)
    response = str(req.text.encode('utf-8'))
    urls = re.findall(r'[-a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)', response)
    for url in urls:
        if 'rest' in url:
            for ext in blacklist:
                if url.endswith(ext):
                    url = url.replace(ext, '')
            return_list.append('http://whois.arin.net'+url)
    return sorted(return_list)


def get_customer_info(customer):
    """Retrieves ARIN Customer Information.

    Args:
        passedCustomer: The URL for the ARIN customer information.

    Returns:
        A list of customer information. The list contains the identified
        netblock, the ARIN company name, the ARIN identifier, the address, the
        type (customer), and the ARIN resource URL. An example is below:

            ['69.224.21.208/29', 'GOOGLE INC-040731031303', 'C00876643',
             'Private Address, Plano, United States, 75075', 'customer',
             'http://whois.arin.net/rest/customer/C00876643'
            ]
    """
    # Local variables
    return_list = []
    net = ''
    name = ''
    handle = ''
    address = ''

    # Request information
    req = requests.get(customer+'.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    # Get information
    handle = parsed['customer']['handle']['$']
    name = parsed['customer']['name']['$']
    ## Network information
    try:
        start_net = parsed['customer']['nets']['netRef']['@startAddress']
        end_net = parsed['customer']['nets']['netRef']['@endAddress']
        net = netaddr.iprange_to_cidrs(start_net, end_net)[0]
    except KeyError:
        net = 'Error: no network information'
    ## Address information
    try:
        return_street = parsed['customer']['streetAddress']['line']['$']
        address += str(return_street)
    except TypeError:
        # If multiple lines for address, get number of lines & iterate
        i = 0
        for line in parsed['customer']['streetAddress']['line']:
            if len(address) <= 0:
                address += str(parsed['customer']['streetAddress']['line'][i]['$']).rstrip()
            else:
                address += ', '+str(parsed['customer']['streetAddress']['line'][i]['$']).rstrip()
            i += 1
    except KeyError:
        address = ''
    try:
        return_city = parsed['customer']['city']['$']
        address += ', '+str(return_city)
    except KeyError:
        None
    try:
        return_country = parsed['customer']['iso3166-1']['name']['$']
        address += ', '+str(return_country)
    except KeyError:
        None
    try:
        return_postal = parsed['customer']['postalCode']['$']
        address += ', '+str(return_postal)
    except KeyError:
        None
    if address[0] == ',':
        address = address.split(',')[1]

    # Return information
    return_list.append(str(net))
    return_list.append(str(name))
    return_list.append(str(handle))
    return_list.append(str(address))
    return_list.append('customer')
    return_list.append(str(customer))
    return return_list


def get_net_info(network):
    """Retrieves ARIN Network Information.

    Args:
        network: The URL for the ARIN network information.

    Returns:
        A list of lists containing network information. The sublist contains the
        identified netblock, the ARIN company name, the ARIN identifier, a blank
        string representing the address (to keep the data formatting consistent
        between ARIN object lists), the type (network), and the ARIN resource
        URL. An example is below:

            [
                ['107.167.160.0/19', 'GOOGLE-CLOUD', 'NET-107-167-160-0-1', '',
                'network', 'http://whois.arin.net/rest/net/NET-107-167-160-0-1']
            ]
    """
    #Local variables
    return_list = []
    net = ''
    name = ''
    handle = ''
    empty = ''

    # Request information
    req = requests.get(network+'.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    # Get information
    handle = parsed['net']['handle']['$']
    name = parsed['net']['name']['$']

    # Network information
    try:
        #If only one network
        net = parsed['net']['netBlocks']['netBlock']['startAddress']['$']
        net += '/'+parsed['net']['netBlocks']['netBlock']['cidrLength']['$']

        # Return information
        temp = []
        temp.append(str(net))
        temp.append(str(name))
        temp.append(str(handle))
        temp.append(str(empty))
        temp.append('network')
        temp.append(str(network))
        return_list.append(temp)
        return return_list
    except TypeError:
        # If multiple networks
        i = 0
        for line in parsed['net']['netBlocks']['netBlock']:
            net = parsed['net']['netBlocks']['netBlock'][i]['startAddress']['$']
            net += '/'+parsed['net']['netBlocks']['netBlock'][i]['cidrLength']['$']
            i += 1

            # Prepare then return information
            temp = []
            temp.append(str(net))
            temp.append(str(name))
            temp.append(str(handle))
            temp.append(str(empty))
            temp.append('network')
            temp.append(str(network))
            return_list.append(temp)
        return return_list


def get_asn_info(asn):
    """Retrieves ARIN ASN Information.

    Args:
        asn: The URL for the ARIN ASN information.

    Returns:
        A list of lists containing ASN network information. The sublist contains
        a netblock within an ASN, the ARIN company name, the ARIN identifier, a
        blank string representing the address (to keep the data formatting
        consistent between ARIN object lists), the type (ASN), and the ARIN
        resource URL. An example is below:

            [
             ['104.132.34.0/24', 'Google LLC', 'AS15169', '', 'asn',
              'http://whois.arin.net/rest/asn/AS15169'],
             ['104.134.126.0/24', 'Google LLC', 'AS15169', '', 'asn',
             'http://whois.arin.net/rest/asn/AS15169']
            ]
    """
    # Local variables
    return_list = []
    nets = []
    handle = ''
    org = ''
    empty = ''

    # Request information
    req = requests.get(asn+'.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    # Get information
    handle = parsed['asn']['handle']['$']
    try:
        org = parsed['asn']['orgRef']['@name']
    except KeyError:
        org = 'Error: No org info'
    ## Get ASN Subnets
    nets = get_asn_subnets(handle)

    # Process ASN Subnets
    for subnet in nets:
        temp = []
        temp.append(str(subnet))
        temp.append(str(org))
        temp.append(str(handle))
        temp.append(str(empty))
        temp.append('asn')
        temp.append(str(asn))
        return_list.append(temp)

    # Return information
    return return_list


def get_asn_subnets(asn):
    """Retrieves networks in an ASN.

    Args:
        asn: The ASN to get network information from.

    Returns:
        A list of netblocks from the asn. If no netblocks were identified,
        a list with a string indicating this is returned instead.
    """
    return_list = []
    headers = {'Host'          : 'ipinfo.io',
               'User-Agent'    : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
               'Accept'        : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip, deflate',
               'Connection'    : 'close'}
    req = requests.get('https://ipinfo.io/'+process_url_encode(asn), headers=headers)
    soup = BeautifulSoup(req.text, 'html.parser')
    for a in soup.find_all('a', text=True):
        if asn in str(a):
            return_list.append(str(a.text).strip())
    if return_list:
        return return_list
    else:
        return_list.append('Error: no networks in ASN')
        return return_list


def get_org_address_info(org):
    """Retrieves address information from an ARIN organization object.

    Args:
        org: The URL for the ARIN organization information.

    Returns:
        A string of the retrieved address.
    """
    # Local variables
    address = ''

    # Request information
    req = requests.get(org+'.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    # Get information
    handle = parsed['org']['handle']['$']
    ## Parse address information
    try:
        return_street = parsed['org']['streetAddress']['line']['$']
        address += str(return_street)
    except TypeError:
        try:
            # If multiple lines for address, get number of lines & iterate
            i = 0
            for line in parsed['org']['streetAddress']['line']:
                if len(address) <= 0:
                    address += str(parsed['org']['streetAddress']['line'][i]['$']).rstrip()
                else:
                    address += ', '+str(parsed['org']['streetAddress']['line'][i]['$']).rstrip()
                i += 1
        except TypeError:
            None
        except KeyError:
            None
    except KeyError:
        None
    try:
        return_city = parsed['org']['city']['$']
        address += ', '+str(return_city)
    except KeyError:
        None
    except TypeError:
        None
    try:
        return_country = parsed['org']['iso3166-1']['name']['$']
        address += ', '+str(return_country)
    except KeyError:
        None
    except TypeError:
        None
    try:
        return_postal = parsed['org']['postalCode']['$']
        address += ', '+str(return_postal)
    except KeyError:
        None
    except TypeError:
        None
    if address[0] == ',':
        address = address.split(',')[1]

    # Return information
    return address.rstrip()


def get_poc_info(poc):
    """Retrieves ARIN point of contact information.

    Args:
        poc: The URL for the ARIN PoC information.

    Returns:
        A list containing point of contact information. The list contains the
        name of the contact, the ARIN company name, the address, the country,
        and the postal code. An example is below:

            ['John Smith', 'Acme Corp',
             '123 Apple Way, Springfield, PA United States, 55401',
             'john.smith@example.com', '+1-123-555-1234'
            ]
    """
    # Local variables
    address = ''
    email = ''
    phone = ''
    return_list = []

    # Request information
    req = requests.get(poc+'.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    # Get name and company information
    name = parsed['poc']['lastName']['$']
    try:
        name = parsed['poc']['firstName']['$'] + ' ' + name
    except KeyError:
        None
    try:
        company = parsed['poc']['companyName']['$']
    except KeyError:
        company = 'No company data'

    # Get address information
    try:
        return_street = parsed['poc']['streetAddress']['line']['$']
        address += str(return_street)
    except TypeError:
        i = 0
        for line in parsed['poc']['streetAddress']['line']:
            if len(address) <= 0:
                address += str(parsed['poc']['streetAddress']['line'][i]['$']).rstrip()
            else:
                address += ', '+str(parsed['poc']['streetAddress']['line'][i]['$']).rstrip()
            i += 1
    try:
        return_city = parsed['poc']['city']['$']
        address += ', '+str(return_city)
    except KeyError:
        None
    try:
        return_country = parsed['poc']['iso3166-1']['name']['$']
        address += ', '+str(return_country)
    except KeyError:
        None
    try:
        return_postal = parsed['poc']['postalCode']['$']
        address += ', '+str(return_postal)
    except KeyError:
        None
    if address[0] == ',':
        address = address.split(',')[1]

    # Get email or emails
    try:
        email = parsed['poc']['emails']['email']['$']
    except TypeError:
        i = 0
        for line in parsed['poc']['emails']['email']:
            if len(email) <= 0:
                email += str(parsed['poc']['emails']['email'][i]['$']).rstrip()
            else:
                email += ', '+str(parsed['poc']['emails']['email'][i]['$']).rstrip()
    except KeyError:
        email = ''

    # Get phone number or numbers
    try:
        phone = str(parsed['poc']['phones']['phone']['number']['$'])
    except TypeError:
        i = 0
        for line in parsed['poc']['phones']['phone']:
            if len(phone) <= 0:
                phone += str(parsed['poc']['phones']['phone'][i]['number']['$']).rstrip()
            else:
                phone += ', '+str(parsed['poc']['phones']['phone'][i]['number']['$']).rstrip()

    # Return information
    return_list.append(name)
    return_list.append(company)
    return_list.append(address)
    return_list.append(email)
    return_list.append(phone)
    return return_list


def get_org_poc_info(org):
    """Retrieves ARIN point of contact information from an organization object.

    Args:
        org: The URL for the ARIN PoC information.

    Returns:
        A list of lists containing point of contact information. The sublist
        contains the name of the contact, the ARIN company name, the address,
        the country, and the postal code. An example is below:

            [
             ['John Smith', 'Acme Corp',
              '123 Apple Way, Springfield, PA United States, 55401',
              'john.smith@example.com', '+1-123-555-1234'
             ]
            ]
    """
    # Local variables
    return_list = []
    links = []

    # Request information
    req = requests.get(org+'/pocs.json')
    response = req.text.encode('utf-8')
    parsed = json.loads(response)

    #Get PoC links
    try:
        links.append(parsed['pocs']['pocLinkRef']['$'])
    except TypeError:
        i = 0
        for line in parsed['pocs']['pocLinkRef']:
            links.append(str(parsed['pocs']['pocLinkRef'][i]['$']).rstrip())
            i += 1

    #Get PoC information from links
    for link in links:
        return_list.append(get_poc_info(link))

    # Return information
    return return_list


def get_ip_coordinates(ip):
    """Retrieves the physical coordinates of an IP address.

    Args:
        ip: The IP address to get coordinates for.

    Returns:
        Returns a string of the coordinates of the ip, if available.
    """
    if '/' in ip:
        ip = ip.split('/')[0]
    headers = {'Host'          : 'ipinfo.io',
               'User-Agent'    : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0',
               'Accept'        : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
               'Accept-Language': 'en-US,en;q=0.5',
               'Accept-Encoding': 'gzip, deflate',
               'Connection'    : 'close'}
    req = requests.get('https://ipinfo.io/'+ip, headers=headers)
    response = req.text
    tree = html.fromstring(response)
    coordinates = tree.xpath(
        '//*[@id=\"content\"]/section[1]/div/div[1]/div/div[1]/div/ul/li[4]/span[2]/text()')
    return ''.join(coordinates)


def get_key_tag(soup, top_result):
    """Finds the nth most popular tag on a webpage.

    Args:
        soup: A Beautiful Soup object of the target's EX-21 document
            (i.e.: subsidiary information).
        top_result: The nth most popular tag to find.

    Returns:
        Returns the tag that is the top_result's value most popular.
    """
    top_result = top_result-1
    all_tags = []
    unique_tags = []
    count_tags = []
    key_tag = ''
    for tag in soup.findAll():
        if tag.name not in unique_tags:
            unique_tags.append(tag.name)
    for tag in soup.findAll():
        all_tags.append(tag.name)
    for tag in unique_tags:
        temp = [int(all_tags.count(tag)), str(tag)]
        count_tags.append(temp)
    count_tags = sorted(count_tags, key=operator.itemgetter(0), reverse=True)
    return str(count_tags[top_result][1])


def get_subsidiaries(company_name, verbose, alt_method, quiet):
    """Returns a list of company subsidiaries.

       Queries the SEC EDGAR database for subsidiary information about a company
       and returns a list of subsidiaries based on the results

    Args:
        company_name: The name of the company that subsidiaires should be
            returned for.
        verbose: A boolean that indicates whether verbose status messages
            should be printed.
        alt_method: A boolean specifying whether the alternative parsing
            method should be used.
        quiet: A boolean that indicates that all status messages should be
            disabled.

    """
    #Local variables
    companies = []
    unique_companies = []
    return_list = []
    dups = []
    document_status = 0
    subsid_enum_count = 0

    # Find Companies and CIKs from given company name
    if not quiet:
        print('[*] Getting subsidiary information for '+str(company_name))
    if verbose:
        print('  [*] Gathering company information for '+str(company_name)+
              ' from EDGAR database')
    else:
        if not quiet:
            print('  [*] Status: 1/3')
    possible_companies = edgar.Edgar(user_agent=USER_AGENT).find_company_name(company_name)
    for company in possible_companies:
        temp = []
        temp.append(company)
        temp.append(edgar.Edgar(user_agent=USER_AGENT).get_cik_by_company_name(company))
        companies.append(temp)

    # Get documents from CIK
    if verbose:
        print('  [*] Gathering company documents for '+str(company_name)+
              ' from EDGAR database')
    else:
        if not quiet:
            print('  [*] Status: 2/3')
    for sub_list in companies:
        if sub_list[1] not in dups:
            dups.append(sub_list[1])
            unique_companies.append(sub_list)
    for sub_company_list in unique_companies:
        document_status += 1
        if verbose:
            print('    [*] Status: '+str(document_status)+'/'+str(len(unique_companies)))
        company = edgar.Company(sub_company_list[0], sub_company_list[1], user_agent=USER_AGENT)
        tree = company.get_all_filings(filing_type='10-K')
        docs = edgar.Company.get_documents(tree, no_of_documents=5)
        sub_company_list.append(len(docs))

    # If no documents were found, remove company
    doc_companies = [sub_company_list for sub_company_list in unique_companies if sub_company_list[2] != 0]
    for sub_list in doc_companies:
        del sub_list[2]
    if doc_companies:
        if verbose:
            print('  [*] Removed companies with no document information, '+str(len(doc_companies))+
                  '/'+str(len(unique_companies))+' remain')
    else:
        if verbose:
            print('  [!] No companies with document information were found for '+str(company_name)+'. Document information is needed to find subsidiaries.')
            print('    [*] Note that when this occurs, it is likely that either the supplied company is a subsidiary if a holding company or that the company')
            print('    [*]  submitted the required filing information via paper. Visit sec.gov/edgar/searchedgar/companysearch.html to find subsidiaries manually.')
        else:
            if not quiet:
                print('  [!] No companies with document information were found for '+str(company_name)+'. Document information is needed to find subsidiaries.')
                print('    [*] Note that when this occurs, it is likely that the supplied company is a subsidiary if a holding company.')
        return return_list

    # Get list of subsidiaries
    for sub_list in doc_companies:
        try:
            ## Variables
            found = False
            found_subsid = False
            found_url = ''
            subsid_url = ''
            subsid_enum_count += 1
            result_list = []

            ## Print status
            if verbose:
                if len(doc_companies) > 1:
                    print('  \n['+str(subsid_enum_count)+'/'+str(len(doc_companies))+
                          '] Getting list of subsidiaries for '+str(sub_list[0]))
                else:
                    print('  [*] Getting list of '+str(company_name)+' subsidiaries')
            else:
                if not quiet:
                    print('  [*] Status: 3/3')

            ## Find Documents in search page and see if EX-21 documents are included
            if verbose:
                print('    [*] Searching filings for EX-21 documents')
            search_page = requests.get('https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK='+sub_list[1]+'&type=10-K&dateb=&owner=exclude&count=100', headers={'User-Agent': USER_AGENT})
            search_tree = html.fromstring(search_page.text)
            elems = search_tree.xpath('//*[@id=\'documentsbutton\']')
            for elem in elems:
                if not found:
                    url = 'https://www.sec.gov' + elem.attrib['href']
                    test_ex21 = requests.get(url, headers={'User-Agent': USER_AGENT})
                    if 'EX-21' in test_ex21.text:
                        found = True
                        found_url = url
            if verbose:
                print('      [*] Found:', found_url)

            ## Download document that contains 'EX-21' in their type
            if verbose:
                print('    [*] Downloading EX-21 document')
            doc_page = requests.get(found_url, headers={'User-Agent': USER_AGENT})
            doc_tree = html.fromstring(doc_page.text)
            for i in range(1, 25):
                if not found_subsid:
                    if 'EX-21' in str(doc_tree.xpath('//*[@id=\'formDiv\']/div/table/tr['+str(i)+']/td[4]/text()')):
                        subsid_url = 'https://www.sec.gov' + str(doc_tree.xpath('//*[@id=\'formDiv\']/div/table/tr['+str(i)+']/td[3]/node()/@href')[0])
                        found_subsid = True
            if verbose:
                print('      [*] Found:', subsid_url)

            ## Get and enumerate subsidiaries
            ## Ensure that a document was retrieved and not a directory
            if subsid_url:
                if subsid_url[-1] != '/':
                    if verbose:
                        print('    [*] Parsing subsidiaries')
                    subsid_page = requests.get(subsid_url, headers={'User-Agent': USER_AGENT})
                    soup = BeautifulSoup(subsid_page.text, 'html.parser')
                    soup_tags = soup.find_all('font', text=True)
                    for tag in soup_tags:
                        filter_result = process_potential_company(tag.text, str(sub_list[0]))
                        if filter_result:
                            result_list.append(filter_result)
                    ### Check to see if low list; if true, try most popular tag
                    if len(result_list) < 5:
                        result_list.clear()
                        key_tag = get_key_tag(soup, 1)
                        soup_tags = soup.find_all(key_tag, text=True)
                        for tag in soup_tags:
                            filter_result = process_potential_company(tag.text, str(sub_list[0]))
                            if filter_result:
                                result_list.append(filter_result)
                        ### Check to see if low list still; if true, try second most popular tag
                        if len(result_list) < 5:
                            result_list.clear()
                            key_tag = get_key_tag(soup, 2)
                            soup_tags = soup.find_all(key_tag, text=True)
                            for tag in soup_tags:
                                filter_result = process_potential_company(tag.text, str(sub_list[0]))
                                if filter_result:
                                    result_list.append(filter_result)
                            ### If we get to this point, it's most likely that the company has a
                            ###  low number of subsidiaries, so return the original list
                            if len(result_list) < 5:
                                result_list.clear()
                                soup_tags = soup.find_all('font', text=True)
                                for tag in soup_tags:
                                    filter_result = process_potential_company(tag.text, str(sub_list[0]))
                                    if filter_result:
                                        result_list.append(filter_result)
                    ## Actions to take if user specified alternative method usage
                    if alt_method:
                        result_list2 = []
                        result_list3 = []
                        ### Try alternative tags to see if more accurate - 1st frequent tag
                        key_tag = get_key_tag(soup, 1)
                        soup_tags = soup.find_all(key_tag, text=True)
                        for tag in soup_tags:
                            filter_result = process_potential_company(tag.text, str(sub_list[0]))
                            if filter_result:
                                result_list2.append(filter_result)
                        ### Try alternative tags to see if more accurate - 2nd frequent tag
                        key_tag = get_key_tag(soup, 2)
                        soup_tags = soup.find_all(key_tag, text=True)
                        for tag in soup_tags:
                            filter_result = process_potential_company(tag.text, str(sub_list[0]))
                            if filter_result:
                                result_list3.append(filter_result)
                        ### Test which list has the most entries
                        if (len(set(result_list)) > len(set(result_list2))) and (len(set(result_list)) > len(set(result_list3))):
                            return_list = sorted(set(result_list))
                        if (len(set(result_list2)) > len(set(result_list))) and (len(set(result_list2)) > len(set(result_list3))):
                            return_list = sorted(set(result_list2))
                        if (len(set(result_list3)) > len(set(result_list))) and (len(set(result_list3)) > len(set(result_list2))):
                            return_list = sorted(set(result_list3))
                    else:
                        for company in set(result_list):
                            return_list.append(company)
        except requests.exceptions.MissingSchema:
            if not quiet:
                print('  [!] ERROR: No EX-21 data found, error fetching subsidiaries')
            else:
                print('  [!] ERROR: Unable to fetch subsidiaries')

    # Return subsidiary results
    return sorted(return_list)


def get_google_networks(target, verbose, quiet):
    """Retrieves networks from Google.

    Args:
        target: A string containing the target company name.
        verbose: A boolean that indicates whether verbose status messages
            should be printed.
        quiet: A boolean that indicates that all status messages should be
            disabled.

    Returns:
        A list of lists containing network information. The sublist contains the
        identified netblock, the company name, the identifier, a blank string
        representing the address (to keep the data formatting consistent between
        ARIN object lists), the type (network), and the resource URL. An example
        is below:

            [
                ['107.167.160.0/19', 'GOOGLE-CLOUD', 'NET-107-167-160-0-1', '',
                'network', 'http://whois.arin.net/rest/net/NET-107-167-160-0-1']
            ]
    """
    # Local variables
    search_term = 'site:ipinfo.io "'+target+'" "netblock details"'
    headers =   {   'Host': 'www.google.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close',
                    'Upgrade-Insecure-Requests': '1'
                }
    results = []
    start_num = 0
    runs = 0
    continue_scrape = True

    # Get Google results
    while continue_scrape == True:
        # Local variables
        recent = []
        runs += 1

        # Print status
        if verbose:
            print('  [*] Status: Parsing page', runs, ' '*20, end='\r')

        # Make request to Google
        try:
            req = requests.get('https://www.google.com/search?hl=en&q='+process_url_encode(search_term)+'&start='+str(start_num), headers=headers, timeout=5)
            start_num += 10

            # Detect CAPTCHA, if present, quit method
            if 'Our systems have detected unusual traffic from your computer network.' in req.text:
                return False
        except requests.exceptions.RequestException as e:
            if not quiet:
                print('\n  [!] ERROR: Requests error:',e )
            continue_scrape = False

        # Get network and IPinfo link from Google result page
        if continue_scrape:
            soup = BeautifulSoup(req.text, 'html.parser')
            for tag in soup.find_all('a', href=True):
                if 'ipinfo.io/' in tag['href']:
                    recent.append(tag)
                    try:
                        # Parse network information from search result
                        network = str(netaddr.IPNetwork(tag.text.split(' ')[0]))
                        url = tag['href']
                        handle = url.split('ipinfo.io/')[1]
                        result_title = tag.text.split('Netblock Details -')[1]
                        # Try to get an identifiable name for the network
                        name = ''
                        if target.lower() in result_title.lower():
                            name = target
                        else:
                            nethandle = get_nethandle(url)
                            if nethandle:
                                arin_nets = get_net_info('https://whois.arin.net/rest/net/'+nethandle)
                                for sublist in arin_nets:
                                    results.append(sublist)
                            else:
                                name = None
                        # If a name was identified, add to results
                        if name:
                            results.append([network, target, handle, '', 'network', url])
                    except netaddr.AddrFormatError:
                        None
                    except IndexError:
                        None

        # Determine if scraping needs to stop
        if len(recent) == 0:
            continue_scrape = False
        try:
            soup_b = BeautifulSoup(req.text, 'html.parser')
            for tag in soup_b.find_all('b', text=True):
                if search_term == tag.text:
                    continue_scrape = False
                    if verbose:
                        print('  [*] Status: Scrape complete')
            if 'In order to show you the most relevant results, we have omitted some entries very similar to' in req.text:
                continue_scrape = False
                if verbose:
                    print('  [*] Status: Scrape complete')
        except NameError:
            None

        # Sleep if more results still need to be scraped
        if continue_scrape:
            num = random.uniform(1,3)
            if verbose:
                print('  [*] Status: Sleeping for', format(num, '.1f'), 'seconds', ' '*20, end='\r')
            time.sleep(num)

    # Return results list
    return results


def get_nethandle(url):
    """Retrieves an ARIN nethandle from an IPinfo network webpage.

    Args:
        url: The URL for an IPinfo network webpage.

    Returns:
        A string containing the ARIN nethandle. If no nethandle is found, None
        is returned. An example is below:

            NET-107-167-160-0-1
    """
    # Local variables
    result = None
    headers =   {   'Host': 'ipinfo.io',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:68.0) Gecko/20100101 Firefox/68.0',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                    'Accept-Language': 'en-US,en;q=0.5',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close',
                    'Upgrade-Insecure-Requests': '1'
                }

    # Request nethandle and process
    handle_req = requests.get(url, headers=headers)
    soup_pre = BeautifulSoup(handle_req.text, 'html.parser')
    for tag in soup_pre.find_all('pre', text=True):
        if 'NetHandle' in tag.text:
            for x in range(0,str(tag.text).count('\n')+1):
                line = str(tag.text).split('\n')[x]
                if 'NetHandle' in line:
                    handle = line.split('NetHandle:')[1].lstrip()
                    result = handle

    # Return result
    return result


def get_statistics(netblock_list, subsid_mode):
    """Prints statistics about final results.

    Args:
        netblock_list: A list of netblocks with identifying information.
        subsid_mode: A boolean indicating whether the status should be printed
            for a subsidiary or a regular company.

    """
    # Return statistics
    asn_count = 0
    cust_count = 0
    net_count = 0
    asn_dups = []
    for sub_list in netblock_list:
        if sub_list[3] == 'asn':
            if sub_list[2] not in asn_dups:
                asn_dups.append(sub_list[2])
                asn_count += 1
        elif sub_list[3] == 'customer':
            cust_count += 1
        elif sub_list[3] == 'network':
            net_count += 1
    if subsid_mode:
        print('\n[*] SUMMARY FOR ALL SUBSIDIARIES')
    else:
        print('\n[*] SUMMARY')
    print('  [*] ASN Count:', '\t', asn_count)
    print('  [*] Network Count:', '\t', net_count)
    print('  [*] IPv4 Count:', '\t', process_ip_count(netblock_list, 4))
    print('  [*] IPv6 Count:', '\t', process_ip_count(netblock_list, 6))
    print('  [*] Customer Count:', '\t', cust_count)
    print()


def get_usage():
    """Returns the usage and help information for this tool.
    """
    return'''
  _   _      _   _     _            _    _____           _
 | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
 |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
 | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
 |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|

%s [options] {target company}
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
    -u        Identifying information to send to SEC, default: "CompanyName Name
                  email@companyname.com". See https://www.sec.gov/os/accessing-edgar-data

    Physical Location:
    -g        Retrieve geolocation data (if available)
    -a        Write netblock address information to output
    -ag       Write netblock address information to output but only if it contains a
                  given string

Examples:
    python NetblockTool.py -v Google
    python NetblockTool.py -so -wv Facebook -o Results
    python NetblockTool.py -gavl companies.txt\n\r
''' % sys.argv[0]


# Launch program
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description='Find netblocks owned by a company', add_help=False, usage=get_usage())
    parser.add_argument('target', help='Target company (exclude "Inc", "Corp", etc.')
    parser.add_argument('-c', '--company-name', help='Company name if different than target (may affect accuracy of confidence scores, use carefully; exclude "Inc", "Corp", etc.)')
    parser.add_argument('-l', '--list', help='List mode; argument is a file with list of companies, one per line', action='store_true')
    parser.add_argument('-n', '--no-wildcard', help='Don\'t perform thorough wildcard queries', action='store_true')
    parser.add_argument('-w', '--wildcard', help='Perform more thorough complete wildcard queries', action='store_true')
    parser.add_argument('-o', '--output', help='File name to write data to (no extension, default is target name)')
    parser.add_argument('-e', '--threshold', help='Only return results greater than a given confidence score')
    parser.add_argument('-g', '--geolocation', help='Retrieve geolocation data (if available)', action='store_true')
    parser.add_argument('-a', '--address-out', help='Write netblock address information to output', action='store_true')
    parser.add_argument('-ag', '--address-grep', help='Write netblock address information to output but only if it contains a given string')
    parser.add_argument('-s', '--subsidiary', help='Fetch subsidiary information and return netblocks of all subsidiaries in addition to initial target', action='store_true')
    parser.add_argument('-sp', '--subsidiary-parse-alt', help='Use alternate parsing method when fetching subsidiary information; use if the default method isn\'t working as expected', action='store_true')
    parser.add_argument('-so', '--subsidiary-out', help='Write subsidiary information to a text file (file=Company_subsidiaries.txt)', action='store_true')
    parser.add_argument('-sn', '--subsidiary-name', help='Company name to use when fetching subsidiaries')
    parser.add_argument('-u', '--user-agent', help='Identifying information to send to SEC, default: "CompanyName Name email@companyname.com". See https://www.sec.gov/os/accessing-edgar-data')
    parser.add_argument('-p', '--poc-out', help='Retrieve and write point of contact information to a text file. Note that retrieval of PoC information will likely take some time.', action='store_true')
    parser.add_argument('-4', '--ipv4', help='Only return IPv4 netblocks', action='store_true')
    parser.add_argument('-6', '--ipv6', help='Only return IPv6 netblocks', action='store_true')
    parser.add_argument('-v', '--verbose', help='Verbose mode', action='store_true')
    parser.add_argument('-q', '--quiet', help='Quiet mode', action='store_true')
    parser.add_argument('-ng', '--no-google', help='Don\'t perform Google Dorking queries', action='store_true')
    args = parser.parse_args()
    arg_target = str(args.target)
    arg_company_name = args.company_name
    arg_list = args.list
    arg_no_wildcard = args.no_wildcard
    arg_wildcard = args.wildcard
    arg_output = args.output
    arg_verbose = args.verbose
    arg_quiet = args.quiet
    arg_threshold = args.threshold
    arg_geo = args.geolocation
    arg_address = args.address_out
    arg_address_grep = args.address_grep
    arg_subsid = args.subsidiary
    arg_subsid_alt = args.subsidiary_parse_alt
    arg_subsid_out = args.subsidiary_out
    arg_subsid_name = args.subsidiary_name
    arg_poc = args.poc_out
    arg_ipv4 = args.ipv4
    arg_ipv6 = args.ipv6
    arg_version = None
    arg_no_google = args.no_google

    # Argument validation
    ## Check to see if both 'no wildcard' and 'wildcard' are set
    if (arg_no_wildcard and arg_wildcard):
        print(sys.argv[0], ': error: Cannot specify both no wildcard (-n) and wildcard (-w) options')
        sys.exit()
    ## Ensure an integer was provided
    if arg_threshold:
        try:
            arg_threshold = int(arg_threshold)
        except ValueError:
            print(sys.argv[0], ': error: Provided value for confidence score threshold must be an integer')
            sys.exit()
    ## Validate & standardize address grep argument
    try:
        if (len(arg_address_grep) > 0 and not arg_address):
            arg_address = True
            arg_address_grep = arg_address_grep.lower()
    except TypeError:
        arg_address_grep = ''
    ## Check to see if 'subsidiary alternate method' is set but 'subsidiary' is not
    if (not arg_subsid and arg_subsid_alt):
        arg_subsid = True
    ## Check to see if 'subsidiary output' is set but 'subsidiary' is not
    if (not arg_subsid and arg_subsid_out):
        arg_subsid = True
    ## Check to see if 'subsidiary name' is set but 'subsidiary' is not
    if (arg_subsid_name and not arg_subsid):
        arg_subsid = True
    ## If 'subsidiary name' and list mode are set
    if (arg_subsid_name and arg_list):
        print(sys.argv[0], ': error: Cannot use custom subsidiary name (-sn) with list mode')
        sys.exit()
    ## If 'subsidiary name' is not set, set it to the target
    if (arg_subsid and not arg_subsid_name):
        arg_subsid_name = arg_target
    ## Check if custom company name and list mode
    if (arg_company_name and arg_list):
        print(sys.argv[0], ': error: Cannot use custom company name (-c) with list mode')
        sys.exit()
    ## Check if verbose and quiet are both true
    if (arg_verbose and arg_quiet):
        print(sys.argv[0], ': error: Cannot use both verbose mode (-v) and quiet mode (-q)')
        sys.exit()
    ## Check IP version
    if (arg_ipv4 and arg_ipv6):
        arg_version = None
    elif arg_ipv4:
        arg_version = 4
    elif arg_ipv6:
        arg_version = 6
    ## Process output
    if not arg_output:
        arg_output = process_output_name(arg_target)+'.csv'
    else:
        if not arg_output.endswith('.csv'):
            arg_output = process_output_name(arg_output)+'.csv'
        else:
            arg_output = process_output_name(arg_output)
    ## Set USER_AGENT
    if args.user_agent:
        USER_AGENT = str(args.user_agent)

    # Print banner
    if not arg_quiet:
        print("""  _   _      _   _     _            _    _____           _
 | \ | | ___| |_| |__ | | ___   ___| | _|_   _|__   ___ | |
 |  \| |/ _ \ __| '_ \| |/ _ \ / __| |/ / | |/ _ \ / _ \| |
 | |\  |  __/ |_| |_) | | (_) | (__|   <  | | (_) | (_) | |
 |_| \_|\___|\__|_.__/|_|\___/ \___|_|\_\ |_|\___/ \___/|_|
 """)

    # Actions to take depending on whether an input list and/or subsidiary processing was specified
    if (not arg_list and not arg_subsid):
        try:
            ## Process query
            if arg_no_wildcard == True:
                query = arg_target
            elif arg_wildcard == True:
                query = '*'+arg_target.replace(' ','*').replace('-','*')+'*'.replace('**','*')
            else:
                query = arg_target+'*'
            results = main(arg_target, arg_company_name, query, arg_verbose, arg_threshold, arg_geo, arg_address, arg_address_grep, arg_version, arg_quiet, arg_poc, arg_no_google)
            if results:
                netblocks = results[0]
                csv_headers = results[1]
                process_output_file(netblocks, process_output_name(arg_output), csv_headers)
                get_statistics(netblocks, arg_subsid)
        except KeyboardInterrupt:
            print('\n\n[!] WARNING: Interrupt signal received, quitting script\n')
            sys.exit()

    elif (arg_list and not arg_subsid):
        companies = []
        company_status = 0
        try:
            with open(arg_target, 'r') as data_file:
                for line in data_file:
                    if len(line.rstrip()) > 0:
                        companies.append(line.rstrip())
        except IOError as e:
            print(sys.argv[0], ':', e)
            print(sys.argv[0], ': Make sure you\'re including the file extension')
            sys.exit()
        for company in companies:
            try:
                company_status += 1
                if arg_no_wildcard:
                    query = company
                elif arg_wildcard:
                    query = '*'+company.replace(' ','*').replace('-','*')+'*'.replace('**','*')
                else:
                    query = company+'*'
                if not arg_quiet:
                    print('\n[*] OVERALL STATUS: '+str(company_status)+'/'+str(len(companies))+'\n')
                results = main(company, None, query, arg_verbose, arg_threshold, arg_geo, arg_address, arg_address_grep, arg_version, arg_quiet, arg_poc, arg_no_google)
                if results:
                    netblocks = results[0]
                    csv_headers = results[1]
                    process_output_file(netblocks, str(process_output_name(company))+'.csv', csv_headers)
                    get_statistics(netblocks, arg_subsid)
            except KeyboardInterrupt:
                print('\n\n[!] WARNING: Interrupt signal received, quitting script\n')
                sys.exit()

    elif (not arg_list and arg_subsid):
        try:
            # Get subsidiary info & treat it like list mode
            companies = []
            for result in get_subsidiaries(arg_subsid_name, arg_verbose, arg_subsid_alt, arg_quiet):
                companies.append(result)
            if arg_verbose:
                print('  [*] Found '+str(len(companies))+' subsidiaries')
                for company in companies:
                    print('    [*] '+str(company))
            if arg_subsid_out:
                with open(str(arg_target)+'_subsidiaries.txt', 'w') as data_file:
                    for company in companies:
                        data_file.write(str(company)+'\n')
            if arg_target not in companies:
                companies.append(str(arg_target))
            companies = process_company_extension(companies)
            company_status = 0
            all_netblocks = []
            for company in companies:
                company_status += 1
                if arg_no_wildcard:
                    query = company
                elif arg_wildcard:
                    query = '*'+company.replace(' ','*').replace('-','*')+'*'.replace('**','*')
                else:
                    query = company+'*'
                if not arg_quiet:
                    print('\n\n[*] OVERALL STATUS: '+str(company_status)+'/'+str(len(companies))+'\n\n')
                results = main(company, None, query, arg_verbose, arg_threshold, arg_geo, arg_address, arg_address_grep, arg_version, arg_quiet, arg_poc, arg_no_google)
                if results:
                    netblocks = results[0]
                    csv_headers = results[1]
                    all_netblocks.append(netblocks)
            # Process combined list before write
            if all_netblocks:
                all_netblocks = [item for sublist in all_netblocks for item in sublist]
                all_netblocks = sorted(all_netblocks, key=operator.itemgetter(4), reverse=True)
                process_output_file(all_netblocks, str(process_output_name(arg_target))+'_subsidiaries.csv', csv_headers)
                get_statistics(all_netblocks, arg_subsid)
        except KeyboardInterrupt:
            print('\n\n[!] WARNING: Interrupt signal received, quitting script\n')
            sys.exit()

    elif (arg_list and arg_subsid):
        list_companies = []
        overall_company_status = 0
        try:
            with open(arg_target, 'r') as data_file:
                for line in data_file:
                    if len(line.rstrip()) > 0:
                        list_companies.append(line.rstrip())
        except IOError as e:
            print(sys.argv[0], ':', e)
            print(sys.argv[0], ': Make sure you\'re including the file extension')
            sys.exit()
        try:
            for init_company in list_companies:
                overall_company_status += 1
                if not arg_quiet:
                    print('\n\n[*] OVERALL STATUS: '+str(overall_company_status)+'/'+str(len(list_companies))+'\n\n')
                company_status = 0
                companies = []
                all_netblocks = []
                # Get subsidiary info
                for result in get_subsidiaries(init_company, arg_verbose, arg_subsid_alt, arg_quiet):
                    companies.append(result)
                if arg_verbose:
                    print('  [*] Found '+str(len(companies))+' subsidiaries')
                    for company in companies:
                        print("    [*] "+str(company))
                if arg_subsid_out:
                    with open(str(init_company)+'_subsidiaries.txt', 'w') as data_file:
                        for company in companies:
                            data_file.write(str(company)+'\n')
                companies.append(init_company)
                companies = process_company_extension(companies)
                # Get netblocks
                for company in companies:
                    if arg_no_wildcard:
                        query = company
                    elif arg_wildcard:
                        query = '*'+company.replace(' ','*').replace('-','*')+'*'.replace('**','*')
                    else:
                        query = company+'*'
                    company_status += 1
                    if not arg_quiet:
                        print('\n\n[*] COMPANY STATUS: '+str(company_status)+'/'+str(len(companies))+'\n\n')
                    results = main(company, None, query, arg_verbose, arg_threshold, arg_geo, arg_address, arg_address_grep, arg_version, arg_quiet, arg_poc, arg_no_google)
                    if results:
                        netblocks = results[0]
                        csv_headers = results[1]
                        all_netblocks.append(netblocks)
                # Process combined list before write
                if all_netblocks:
                    all_netblocks = [item for sublist in all_netblocks for item in sublist]
                    all_netblocks = sorted(all_netblocks, key=operator.itemgetter(4), reverse=True)
                    process_output_file(all_netblocks, str(process_output_name(init_company))+'_subsidiaries.csv', csv_headers)
                    get_statistics(all_netblocks, arg_subsid)
        except KeyboardInterrupt:
            print('\n\n[!] WARNING: Interrupt signal received, quitting script\n')
            sys.exit()
