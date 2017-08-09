volatility-misp
======

# volatility-misp - Volatility plugin to interface with MISP

volatility-misp is a [volatility](https://github.com/volatilityfoundation/volatility) plugin that allows to pull [yara](https://github.com/virustotal/yara) rules from a MISP instance's yara attributes and use them in yarascan.

__This is a work in progress__, no documentation available yet

## Requirements

 * Python 2.7 if used as a volatility module
 * Python 2.7 or 3+ if used as a library (excluding volatility_misp.py)
 * [PyMISP](https://github.com/MISP/PyMISP)
 * [yara-python](https://github.com/VirusTotal/yara-python)
 * [volatility](https://github.com/volatilityfoundation/volatility)

## Current capabilities

 * Pulling yara rules from a MISP server
 * Sorting valid yara rules from broken rules
 * Suggesting fixes for some of the broken rules (*currently unused*)
 * Running the valid yara rules on a memory dump (*same capabilities and options as yarascan*)