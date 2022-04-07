<h1 align="center">
  <a href="https://fullhunt.io/"><img src="https://dkh9ehwkisc4.cloudfront.net/static/files/2bcb1bb9-7c6f-4013-83a7-39774bd40e68-1.png" alt="spring4shell-scan"></a>
  <br>
</h1>
<h1 align="center">spring4shell-scan</h1>

<h4 align="center">A fully automated, reliable, and accurate scanner for finding Spring4Shell and Spring Cloud RCE vulnerabilities</h4>



![](https://dkh9ehwkisc4.cloudfront.net/static/files/8b677a1b-7c53-40b1-933e-e10f571c8bb8-spring4shell-Demo.png)


# Features

- Support for lists of URLs.
- Fuzzing for more than 10 new Spring4Shell payloads (previously seen tools uses only 1-2 variants).
- Fuzzing for HTTP GET and POST methods.
- Automatic validation of the vulnerability upon discovery.
- Randomized and non-intrusive payloads.
- WAF Bypass payloads.

---

# Description

The Spring4Shell RCE is a critical vulnerability that FullHunt has been researching since it was released. We worked with our customers in scanning their environments for Spring4Shell and Spring Cloud RCE vulnerabilities.

We're open-sourcing an open detection scanning tool for discovering Spring4Shell (CVE-2022-22965) and Spring Cloud RCE (CVE-2022-22963) vulnerabilities. This shall be used by security teams to scan their infrastructure, as well as test for WAF bypasses that can result in achieving successful exploitation of the organization's environment.

If your organization requires help, please contact (team at fullhunt.io) directly for a full attack surface discovery and scanning for the Spring4Shell vulnerabilities.

# Usage

```python
$ ./spring4shell-scan.py -h
[•] CVE-2022-22965 - Spring4Shell RCE Scanner
[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
[•] Secure your External Attack Surface with FullHunt.io.
usage: spring4shell-scan.py [-h] [-u URL] [-p PROXY] [-l USEDLIST] [--payloads-file PAYLOADS_FILE] [--waf-bypass] [--request-type REQUEST_TYPE] [--test-CVE-2022-22963]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Check a single URL.
  -p PROXY, --proxy PROXY
                        Send requests through proxy
  -l USEDLIST, --list USEDLIST
                        Check a list of URLs.
  --payloads-file PAYLOADS_FILE
                        Payloads file - [default: payloads.txt].
  --waf-bypass          Extend scans with WAF bypass payloads.
  --request-type REQUEST_TYPE
                        Request Type: (get, post, all) - [Default: all].
  --test-CVE-2022-22963
                        Test for CVE-2022-22963 (Spring Cloud RCE).

```

## Scan a Single URL

```shell
$ python3 spring4shell-scan.py -u https://spring4shell.lab.secbot.local
```

## Discover WAF bypasses against the environment

```shell
$ python3 spring4shell-scan.py -u https://spring4shell.lab.secbot.local --waf-bypass
```

## Scan a list of URLs

```shell
$ python3 spring4shell-scan.py -l urls.txt
```

## Include checks for Spring Cloud RCE (CVE-2022-22963)

```shell
$ python3 spring4shell-scan.py -l urls.txt --test-CVE-2022-22963

```

# Installation

```
$ pip3 install -r requirements.txt
```

# Docker Support

```shell
git clone https://github.com/fullhunt/spring4shell-scan.git
cd spring4shell-scan
sudo docker build -t spring4shell-scan .
sudo docker run -it --rm spring4shell-scan

# With URL list "urls.txt" in current directory
docker run -it --rm -v $PWD:/data spring4shell-scan -l /data/urls.txt
```

# About FullHunt

FullHunt is the next-generation attack surface management (ASM) platform. FullHunt enables companies to discover all of their attack surfaces, monitor them for exposure, and continuously scan them for the latest security vulnerabilities. All, in a single platform, and more.

FullHunt provides an enterprise platform for organizations. The FullHunt Enterprise Platform provides extended scanning and capabilities for customers. FullHunt Enterprise platform allows organizations to closely monitor their external attack surface, and get detailed alerts about every single change that happens. Organizations around the world use the FullHunt Enterprise Platform to solve their continuous security and external attack surface security challenges.

# Legal Disclaimer
This project is made for educational and ethical testing purposes only. Usage of spring4shell-scan for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.


# License
The project is licensed under MIT License.


# Author
*Mazin Ahmed*
* Email: *mazin at FullHunt.io*
* FullHunt: [https://fullhunt.io](https://fullhunt.io)
* Website: [https://mazinahmed.net](https://mazinahmed.net)
* Twitter: [https://twitter.com/mazen160](https://twitter.com/mazen160)
* Linkedin: [http://linkedin.com/in/infosecmazinahmed](http://linkedin.com/in/infosecmazinahmed)
