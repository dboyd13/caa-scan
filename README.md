caa-scan
------------

**Purpose:**

A simple scanner that aims to determine [DNS CAA (Certificate Authority Authorization)](https://tools.ietf.org/html/rfc6844) adoption for [HTTPS enabled Alexa Top 1 million websites](https://censys.io/data).

See [this blog post](https://darranboyd.wordpress.com/2017/04/18/dns-caa-record-adoption-scanner-and-results/)

**Prerequisites:**

*Software:*

- python
- hashlib - `sudo pip install hashlib`
- lz4tools - `sudo pip install lz4tools`
- twython - `sudo pip install twython`

*API Keys:*

- [censys.io](https://censys.io/account)
- [apps.twitter.com](https://apps.twitter.com)

**Installation:**

- copy config-sample.ini to config.ini
- Update config.ini with Censys.io API details
- Update config.ini with Twitter API details (optional)

**Usage:**

`python caa-scan.py [config-file]`

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
