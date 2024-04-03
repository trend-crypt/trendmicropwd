# trendmicropwd

Python port and support for additional crypto methods added to `trendmicropwd.c` originally developed by Luigi Auriemma (Copyright 2008). Original program can be found [here](https://aluigi.altervista.org/pwdrec.htm).

Requires Python 3.8 or above. It is also recommended to install the latest version of PyCryptodome, although this is technically not needed for the main script.

`pip install pycryptodome`

I wrote this script because I couldn't find any other information online about some of the newer encryption methods. This script is only intended to be used for educational purposes or by authorized security testing personnel.

# Usage

Run the script with a file as a commandline argument. The file should contain key-value entries normally found in trend Micro configuration (.ini) files. The provided `samples.txt` file contains samples of what this looks like. Spaces before and after the equal sign will be ignored since the formatting of the actual configuration files seems inconsistent.

```bash
./trendmicropwd.py samples.txt

TrendMicro passwords decryptor (2023.10.22)
original work by Luigi Auriemma (aluigi.org)

CensusQueryToken  = census.osce.1400
Ini1.Key  = aucfg.ini,,ignore_zip_index
URLFilterAWSL_InOffice000  = http://www.trendmicro.com/*
Std_Alert_SNMP_Community  = public
```

### Notes for some crypto methods

To properly decrypt `CRYPTCSTEX` strings, the script expects an `InstallDateTime` key-value pair to be added to the target file before any `CRYPTCSTEX` strings. For further details, see the section for this method in NOTES.md.

`CRYPTCSTEX` encrypted strings can be bruteforced. See the NOTES.md file for further details.

To properly decrypt `CRYPTNG` or `CRYPTNGS` strings, the script expects an `skos` key-value pair to be added to the target file before any `CRYPTNG` or `CRYPTNGS` strings. For further details, see the section for this method in NOTES.md.
