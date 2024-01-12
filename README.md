# Generate Cryptographic Inventory from Qualys data

## Overview

This script downloads and deconstructs the results of QID 38116 to determine TLS/SSL protocols enabled for network 
services, the IP addresses and ports on which these services operate, and the individual ciphers contained in the cipher
suites offered by those services.

## Installation

This script requires the following Python modules
```
requests
openpyxl
xmltojson
```

To install these packages using pip:

```commandline
pip -r requirements.txt
```
## Usage

```
generate_inventory.py [-h] [--username USERNAME] [--password PASSWORD] [--apiurl APIURL] [--outputfile OUTPUTFILE]

options:
  -h, --help            show this help message and exit
  --username USERNAME   API Username
  --password PASSWORD   API Password
  --apiurl APIURL       API Base URL (e.g. https://qualysapi.qualys.com)
  --outputfile OUTPUTFILE
                        Name of output file
```

## Identifying your API URL

The following guide will help identify the API URL to use in this script.  Use the entry in the 'API Server URL' column
from the 'API URLs' table which corresponds to your Platform.

https://www.qualys.com/platform-identification/
