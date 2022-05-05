# SSH lookup - Perform lookups on a Passive-SSH platform

A simple script to parse cowrie logs (and WiP pcap files) and query Passive-SSH
The queries results can be pushed in MISP

## Features

The `src_ip` fields of the logs or packets are used for the Passive-SSH queries since they are the potential attackers address

If the address in known in Passive-SSH, the query result contain:
- The SSH banner
- The SSH connection hassh fingerprint
- The related SSH fingerprints

More information about Passive-SSH and how to install and run your own instance: [here](https://github.com/D4-project/passive-ssh)

The information that is pushed then to MISP is the following:
- `network-connection` objects containing data from the SSH connections gathered from the logs / packets:
  - `src_ip` & `dst_ip` (that is sometimes a `domain` or `hostname`)
  - `src_port` & `dst_port`
  - `timestamp`
- `passive-ssh` objects with references to the related `network-connection` objects, when the address is known by Passive-SSH
  - The `host` attribute is the `ip-src` attribute from the `network-connection` object
  - `banner`
  - `ssh-fingerprint`
  - `hassh-md5` fingerprint
  - `banner`
  - `first_seen` & `last_seen`

Everything included in one single script call (data loaded and queried) is pushed into one single MISP event

## Requirements

- Python >= 3.6
- An access to Passive-SSH
- An access to a MISP server, with an auth key

## Install

~~~~
./install.sh
~~~~

- Install python requirements
- All Python 3 code will be installed in a virtualenv (venv)

## Config

Access to our Passive-SSH platform:
geekweek:RUyddR3ccRxR9yxFFQNSU94Aa9LkfASwuGZWr/iQynM=


## Usage

~~~~
python3 ssh_lookup.py logs --csvinput YOUR_SSH_LOGS.cvs --misp --savejson
~~~~

#### Arguments

- `logs` to load CSV or JSON logs from cowrie
  - `--csvinput` or `--jsoninput` depending on the file format
  - `--passivessh_input` in case you already ran requests for the given logs, and want to skip this part to simply push the data to MISP
  - `--misp` to push the query results to MISP
  - `--savejson` in case of a CSV input, to save the JSON converted format for further use
  - `--name` in case the honeypot name in the CSV logs is not cowrie (expect some field names issue if the fields are not the same as the ones mentioned above in [Features](#Features))
- `pcap` to parse pcap files (WiP)
  - `--input`: PCAP files to parse
  - `--misp`: same as above, to push the results on MISP
