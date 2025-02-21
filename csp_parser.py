from __future__ import print_function

from requests import get, exceptions
import click
from socket import gethostbyname, gaierror
from sys import version_info, exit

import sys
import os
import logging
import tldextract
import json
import whois

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s"
)

logger = logging.getLogger('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

__author__ = "Softcake(github.com/chirunnuj)"
__version__ = "0.0.1"
__purpose__ = '''Parse and print domain names from Content Security Policy(CSP) header'''


class Domain:
    def __init__(self, domain=None, apex_domain=None, available=None, ip=None, raw_csp_url=None):
        self.domain = domain
        self.apex_domain = apex_domain
        self.available = available
        self.ip = ip
        self.raw_csp_url = raw_csp_url


def read_file(file_name):
    try:
        with open(file_name, "r") as file:
            urls = file.readlines()
        
        urls = [url.strip() for url in urls]

        for url in urls:
            print(url)

        return urls        
    except FileNotFoundError:
        print(f"Error: the file '{file_name}' was not found.")
        exit(1)
    except Exception as e:
        print(f"An error occured: {e}")
        exit(1)

def write_file(file, url, resolve, check_whois):
    file_handle = None

    if not os.path.exists(file):
        file_handle = open(file, "x")
    else:
        file_handle = open(file, "a")
    
    csp_header = get_csp_header(url)
    if csp_header is not None:
        # Retrieve list of domains "clean" or not
        domains = get_domains(csp_header)
        if resolve:
            domains = resolve_domains(domains)
        if check_whois:
            domains = check_whois_domains(domains)
                
        for domain in domains:
            print(domain.domain)
            file_handle.write(domain.domain + "\n")

        file_handle.close()

def process_single_url(url, resolve, check_whois, output):
    dir = os.getcwd() + "/out"
    if not os.path.exists(dir):
        os.makedirs(dir)

    extracted_url = tldextract.extract(str(url))
    filename = ''
    if extracted_url.subdomain != "":
        filename = '_'.join((extracted_url.subdomain, extracted_url.domain, extracted_url.suffix))
    else:
        filename = '_'.join((extracted_url.domain, extracted_url.suffix))        
        
    file = dir + "/" + filename
    write_file(file, url, resolve, check_whois)   


def process_multiple_urls(urls, resolve, check_whois, output):
    dir = os.getcwd() + "/out"
    if not os.path.exists(dir):
        os.makedirs(dir)
    
    for url in urls:
        extracted_url = tldextract.extract(str(url))
        filename = ''
        if extracted_url.subdomain != "":
            filename = '_'.join((extracted_url.subdomain, extracted_url.domain, extracted_url.suffix))
        else:
            filename = '_'.join((extracted_url.domain, extracted_url.suffix))        
        
        file = dir + "/" + filename       
        write_file(file, url, resolve, check_whois)                


def clean_domains(domains):
    for domain in domains:        
        ext = tldextract.extract(str(domain.raw_csp_url))
        #logger.info(ext)
        # If subdomain is wildcard or empty        
        if ext.subdomain in ['*', '']:
            # Join all but the subdomain (a wildcard or empty)            
            domain.domain = '.'.join((ext.domain, ext.suffix))
        else:            
            domain.domain = '.'.join((ext.subdomain, ext.domain, ext.suffix))        
        
        domain.apex_domain = ".".join((ext.domain, ext.suffix))
    return domains


def get_csp_header(url):
    try:
        logger.info("[+] Fetching headers for {}".format(url))
        r = get(url)
    except exceptions.RequestException as e:
        print(e)
        exit(1)

    if 'Content-Security-Policy' in r.headers:
        csp_header = r.headers['Content-Security-Policy']
        return csp_header
    elif 'content-security-policy-report-only' in r.headers:
        csp_header = r.headers['content-security-policy-report-only:']
        return csp_header
    else:
        logger.info("[+] {} doesn't support CSP header".format(url))
        return None
        # exit(1)


def get_domains(csp_header):
    domains = []
    csp_header_values = csp_header.split(" ")
    for line in csp_header_values:
        if "." in line:
            line = line.replace(";", "")
            domains.append(Domain(raw_csp_url=line))
            #logger.info(Domain(raw_csp_url=line).domain)
        else:
            pass
    return clean_domains(domains)


def resolve_domains(domains):
    # To resolve the domains, we need to clean them
    for domain in clean_domains(domains):
        try:
            ip_address = gethostbyname(domain.domain)
            domain.ip = ip_address
            print("\033[92m{0:<30} - {1:20}\033[1;m".format(domain.domain, ip_address.rstrip("\n\r")))
        except gaierror as e:
            print("\033[93m{0:<30} - {1:20}\033[1;m".format(domain.domain, "No A record exists"), end=''),
            print(e.message)
    return domains


def check_whois_domains(domains):
    # TODO - Check apex domains once instead of for each domain stored (the same apex domain may appear several times)
    for domain in domains:
        details = whois.whois(domain.apex_domain)
        if details.get('status') is None:
            print("[!] Domain available for registering: {}".format(domain.apex_domain))
            domain.available = True
        else:
            print("[i] Domain registered: {}".format(domain.apex_domain))
            domain.available = False
    return domains


def print_output_to_screen(domains):
    for domain in domains:
        print(domain.domain)


@click.command()
@click.option('--file', '-f', required=False,
              help='File contains list of URLs to retrieve the CSP header from')
@click.option('--url', '-u', required=False,
              help='Url to retrieve the CSP header from')
@click.option('--resolve/--no-resolve', '-r', default=False,
              help='Enable/Disable DNS resolution')
@click.option('--check-whois/--no-check-whois', '--whois', default=False,
              help='Check for domain availability')
@click.option('--output', '-o', default=False,
              help='Save results into a json file')

def main(file, url, resolve, check_whois, output):
    if file:        
        urls = read_file(file)
        process_multiple_urls(urls, resolve, check_whois, output)
        
        exit(0)
    else:
        process_single_url(url, resolve, check_whois, output)
        exit(0)
    
    # csp_header = get_csp_header(url)
    # # Retrieve list of domains "clean" or not
    # domains = get_domains(csp_header)
    

    # if resolve:
    #     domains = resolve_domains(domains)
    # if check_whois:
    #     domains = check_whois_domains(domains)
    # if output:
    #     with open(output, 'w') as outfile:
    #         json.dump(dict(domains=[ob.__dict__ for ob in domains]), outfile, sort_keys=True, indent=4)
    # else:
    #     print_output_to_screen(domains)

if __name__ == '__main__':
    main()
