# CyberGreen Scanner and Policy+Cache Server

This artifact accompanies the [poster](ndss24/poster.pdf) presented at the Network and Distributed System Security Symposium (NDSS) 2024.

This public open source release contains:
- The [dataset](dataset/README.md) of 401K Government hostnames curated by combining (and retaining portions) of the following datasets:
  - [Et Tu Brute](https://github.com/nayanamana/PhD/tree/5850b67f8a31f16721076b095c37e67fe43b08e6/priv_analysis_govt_sites) (100%)
  - [Gov-HTTPS](https://github.com/uw-ictd/GovHTTPS-Data) (100%)
  - [Domcop 10M](https://www.domcop.com/top-10-million-websites) (1.21%)
  - [Tranco 1M](https://tranco-list.eu/#download) (2.93%)
  - [CrUX](https://developer.chrome.com/docs/crux) (2.91%)
  - [Majestic 1M](https://majestic.com/reports/majestic-million) (1.16%)
  - [Umbrella 1M](https://s3-us-west-1.amazonaws.com/umbrella-static/index.html) (1.11%)
  - [CISA](https://github.com/cisagov/dotgov-data) (100%)
  - [GSA](https://github.com/GSA/govt-urls) (100%)
  - [Alexa 1M](http://web.archive.org/web/20230803120013/http://s3.amazonaws.com/alexa-static/top-1m.csv.zip) (0.91%)
  - [Cloudflare Radar](https://radar.cloudflare.com/domains) (0.75%)
  - [Gov Cookies](https://govcookies.github.io/) (100%)
  - [Gov UK Domains](https://www.gov.uk/government/publications/list-of-gov-uk-domain-names) (100%)
  - [DOT MIL](https://github.com/esonderegger/dotmil-domains/blob/master/dotmil-domains.csv) (100%)
  - [Built With 1M](https://builtwith.com/top-1m) (0.20%)
  - [ARMY MIL](https://www.army.mil/a-z/) (100%)
  - [Know Nepal](https://github.com/Know-Nepal/government-websites) (100%)
 
## Scanner

### Build instructions

The tool in this repository uses `make` as the build system and generates two binaries during build.

```shell
$ make
```

On successful build, there are two binaries `bin/scan` and `bin/server` which are generated.

### Usage Details (Running a Scan)

`bin/scan` contains three integrated modules which perform the DNS, TLS and Mail scans and can be invoked
by running the commands below. Please run the server `bin/server` prior to the scan commands or use the appropriate flags
`--noserver` to disable caching:
1. `bin/scan dns <args>?`
2. `bin/scan tls <args>?`
3. `bin/scan mail <args>?`

The tool expects a fully qualified domain name `FQDN` to be passed as an argument to `--hostname` available across
all three modules listed above. The following table lists additional arguments and the associated defaults:

| **Argument**   | **Description**                                          | **Default**                                                             |
|----------------|----------------------------------------------------------|-------------------------------------------------------------------------|
| `--hostname`   | Hostname of the domain to query                          | google.com.                                                             |
| `--query-type` | DNS Record Type to query                                 | A                                                                       |
| `--out-dir`    | Output directory to save the results                     | results/                                                                |
| `--out-file`   | Name of the file to save the results as                  | If not provided, a timestamped file is generated with the module prefix |
| `--json`       | Saves the files to disk at the output directory provided | false                                                                   |
| `--pretty`     | Formats the results into a well formatted JSON file      | false                                                                   |

> **Note**
> The mail scanner looks up the required MX record for a provided hostname. Please do not provide the MX record as the hostname argument and instead provide the details of the domain name associated with the MX records. The mail scanner also does all the operations a TLS scanner does but both submodules are port restricted.

> **Warning**
> This is a research prototype and the result format could change. Please exercise caution when using.

### Server

`bin/server` contains a server which provides a caching layer and performs the role of Access Control and Filtering given a set of blocked IPs provided to the server in a block list file argument or default at `dataset/unscanned_ips.txt`.

The filter list entries follow the following formats:
```txt
IP_Address
IP_Address/CIDR
```

> **Warning**
> We do not support filtering by hostname or SNI information for TLS requests and only filter by IP.

Please run the server by executing `bin/server` on a terminal or as a service and keep it running. The execution loads the carefully curated `dataset/cached_tlds.txt` records and prepares the scanner for performing large scale scans.
The `bin/scan` tool can be used once the server has initialized and the progress bar completes indicating cache is ready.
