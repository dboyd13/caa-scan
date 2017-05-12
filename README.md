caa-scan
------------

**Purpose:**

A simple scanner that aims to determine [DNS CAA (Certificate Authority Authorization)](https://tools.ietf.org/html/rfc6844) adoption for [HTTPS enabled Alexa Top 1 million websites](https://censys.io/data).

See [this blog post](https://darranboyd.wordpress.com/2017/04/18/dns-caa-record-adoption-scanner-and-results/)

**Prerequisites:**

*Software:*

- python
- pip (sudo apt-get install python-setuptools python-dev build-essential && sudo easy_install pip)
- dnspython >= v1.12 - `sudo pip install dnspython -U`
- requests - `sudo pip install requests`
- lz4tools - `sudo pip install lz4tools`
- twython - `sudo pip install twython`
- hashlib - `sudo pip install hashlib`

*API Keys:*

- [censys.io](https://censys.io/account)
- [apps.twitter.com](https://apps.twitter.com)

**Installation:**

- git clone this repo
- copy config-sample to config.ini
- Update config.ini with Censys.io API details
- Update config.ini with Twitter API details (optional)

**Usage:**

`python caa-scan.py [config-file]`

**Example:**

    $ python caa-scan.py config-test.ini
    [-] Config: file config-test.ini specified as argument, will try use that
    [-] Censys API: Determining latest dataset for 443-https-tls-alexa_top1mil
    [-] Censys API: Latest is 20170510T103351
    [-] Censys API: Latest is SHA256: 9a44eacb6316e4dcf2e0e02e784a0d21e621a359926d3a862b57a551046c09d3
    [-] Local file SHA256: 9a44eacb6316e4dcf2e0e02e784a0d21e621a359926d3a862b57a551046c09d3
    [-] Local file hash matches - already have the latest dataset
    [-] Running against 679003 HTTPS enabled of Alexa 1m sites
    ok.ru,NO CAA RECORD
    google.com.mx,NO CAA RECORD
    amazon.co.jp,NO CAA RECORD
    amazon.co.uk,NO CAA RECORD
    amazon.in,NO CAA RECORD
    google.com,,0 issue "pki.goog"
    google.com,,0 issue "pki.goog",0 issue "symantec.com"
    <snip>

**Program execution flow:**

1. Checks if config filename argument has been provided, if not defaults to `config.ini`
2. Loads config from file
3. Connects to Censys.io API to determine SHA-256 of latest file.
4. Checks if local file SHA-256 matches, if matches then doesn't download
5. If local SHA-256 doesn't match, or loca file doesn't exist, then downloads the latest file
6. Decompresses the .lz4 file to produce .csv
7. Queries DNS for CAA record (Type 257), for each host in the .csv
8. Prints each parsed response to STDOUT (if enabled in config file)
9. Reports interim progress to HTML file (if enabled in config file)
10. Writes valid CAA responses to file (if enabled in config file)
11. Reports final results to HTML file (if enabled in config file)
12. Tweets the final results to a twitter account (if enabled in config file)
