#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# spring4shell-scan: A generic scanner for Spring4Shell CVE-2022-22965 and CVE-2022-22963
# Author:
# Mazin Ahmed <mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************


import argparse
import random
import requests
import sys
from urllib import parse as urlparse
from termcolor import cprint

# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2022-22965 - Spring4Shell RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")


if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'spring4shell-scan (https://github.com/fullhunt/spring4shell-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.60 Safari/537.36',
    'Accept': '*/*'
}

timeout = 4


def get_random_string(length=7):
    return ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(length))


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="Send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs.",
                    action='store')
parser.add_argument("--payloads-file",
                    dest="payloads_file",
                    help="Payloads file - [default: payloads.txt].",
                    action='store',
                    default="payloads.txt")
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post, all) - [Default: all].",
                    default="all",
                    action='store')
parser.add_argument("--test-CVE-2022-22963",
                    dest="test_cve_2022_22963",
                    help="Test for CVE-2022-22963 (Spring Cloud RCE).",
                    action='store_true')

args = parser.parse_args()

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})


def set_url_path(url, path="/"):
    url_parsed = parse_url(url)
    return f'{url_parsed["site"]}{path}'


def get_waf_bypass_payloads():
    random_string = get_random_string()
    payloads = []
    with open(args.payloads_file, "r") as f:
        for payload in f.readlines():
            payload = payload.replace("{{random}}", random_string)
            payloads.append(payload.strip())
    print(payloads)
    return payloads


def verify_base_request(url, method):
    r = requests.request(url=url,
                         method=method,
                         headers=default_headers,
                         verify=False,
                         timeout=timeout,
                         proxies=proxies)
    return r.status_code


def test_url_cve_2022_22965(url):
    main_payload = "class.module.classLoader[{{random}}]={{random}}"
    main_payload = main_payload.replace("{{random}}", get_random_string())
    payloads = []
    payloads.append(main_payload)
    if args.waf_bypass_payloads:
        payloads.extend(get_waf_bypass_payloads())

    for payload in payloads:
        parameter, value = payload.split("=")
        cprint(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")

        if args.request_type.upper() in ("POST", "ALL"):
            try:
                r = requests.request(url=url,
                                     method="POST",
                                     headers=default_headers,
                                     verify=False,
                                     timeout=timeout,
                                     data={parameter: value},
                                     proxies=proxies)
                if r.status_code not in (200, 404) and verify_base_request(url, "POST") != r.status_code:
                    return True
            except Exception as e:
                cprint(f"EXCEPTION: {e}")
        if args.request_type.upper() in ("GET", "ALL"):
            try:
                r = requests.request(url=url,
                                     method="GET",
                                     headers=default_headers,
                                     verify=False,
                                     timeout=timeout,
                                     params={parameter: value},
                                     proxies=proxies)
                if r.status_code not in (200, 404) and verify_base_request(url, "GET") != r.status_code:
                    return True
            except Exception as e:
                cprint(f"EXCEPTION: {e}")
    return False


def test_cve_2022_22963(url):
    random_string = get_random_string()
    headers = {}
    headers.update(default_headers)
    url = set_url_path(url, path="/functionRouter")
    cprint(f"[•] URL: {url}", "cyan")

    headers.update({"spring.cloud.function.routing-expression": random_string})
    try:
        r = requests.request(url=url,
                             method="POST",
                             verify=False,
                             timeout=timeout,
                             data=random_string,
                             headers=headers,
                             proxies=proxies)
        if r.status_code not in (200, 404) and verify_base_request(url, "POST") != r.status_code:
            return True
    except Exception as e:
        cprint(f"EXCEPTION: {e}")

    return False


def main():
    urls = []
    if args.url:
        urls.append(args.url)
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                i = i.strip()
                if i == "" or i.startswith("#"):
                    continue
                urls.append(i)

    vulnerable_hosts = []
    for url in urls:
        cprint(f"[•] URL: {url}", "magenta")
        cprint("[%] Checking for Spring4Shell RCE CVE-2022-22965.", "magenta")
        result = test_url_cve_2022_22965(url)
        if result:
            cprint("[!!!] Target Affected (CVE-2022-22965)", "yellow")
            vulnerable_hosts.append(url)
        else:
            cprint("[•] Target does not seem to be vulnerable.", "green")

        if args.test_cve_2022_22963:
            cprint("[%] Checking for Spring Cloud RCE CVE-2022-22963.", "magenta")
            result = test_cve_2022_22963(url)
            if result:
                cprint("[!!!] Target Affected (CVE-2022-22963)", "yellow")
                vulnerable_hosts.append(url)
            else:
                cprint("[•] Target does not seem to be vulnerable.", "green")

    if len(vulnerable_hosts) == 0:
        cprint("[•] No affected targets were discovered.", "green")
    else:
        cprint(f"[!] Total Vulnerable Hosts: {len(vulnerable_hosts)}", "yellow")
        for host in vulnerable_hosts:
            cprint(f"[!] {host}", "red")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
