import argparse
import csv
import json
import logging
import os
import requests
import sys
from collections import defaultdict
from pathlib import Path
from pymisp import PyMISP, MISPEvent, MISPObject

_CONFIG_PATH = Path(__file__).resolve().parent / 'config'
_PASSIVE_SSH_FIELDS = ('banner', 'hassh', 'keys')


def _clean_tmp_files(savejson, parsed_files):
    if not savejson:
        for parsed_file in parsed_files:
            os.remove(parsed_file)


def _csv_to_json(filename, honeypot_name):
    try:
        lines = tuple(csv.reader(_fix_nulls(open(filename)), delimiter=','))
    except FileNotFoundError:
        print(f"Unknown input file: {filename}.", file=sys.stderr)
        return []
    header = lines[0]
    for line in lines:
        parsed_line = {key: value for key, value in zip(header, line) if value}
        feature = parsed_line['category'] if 'category' in parsed_line else parsed_line['data'] if 'data' in parsed_line else 'undefined'
        if feature == honeypot_name:
            yield parsed_line


def _fix_nulls(csv_file):
    for line in csv_file:
        yield line.replace('\0', '')


def _perform_queries(filename, honeypot_name, passive_ssh_url, authentication):
    _write_json_logs(filename, honeypot_name)
    ip_addresses = {log['src_ip'] for log in logs}
    passive_ssh_records = {}
    for ip_address in ip_addresses:
        try:
            query = requests.get(f'{passive_ssh_url}/host/ssh/{ip_address}', auth=authentication)
        except Exception as e:
            print(f'Error while processing your query: {e}', file=sys.stderr)
            return 404
        if query.status_code != 200:
            if query.reason == 'Unauthorized':
                return 401
            message = f'{ip_address}: {query.status_code} - {query.reason}'
            print(f'Error while querying Passive-SSH with the IP address {message}', file=sys.stderr)
            continue
        result = query.json()
        if any(result.get(feature) for feature in _PASSIVE_SSH_FIELDS):
            passive_ssh_records[ip_address] = result
    if passive_ssh_records:
        with open(f'{filename}.passivessh.json', 'wt', encoding='utf-8') as f:
            f.write(json.dumps(passive_ssh_records, indent=4))
        return 200
    return 0


def _push_misp_data(parsed_files):
    first_seen = float('inf')
    last_seen = 0

    with open(_CONFIG_PATH / 'misp_config.json', 'rt', encoding='utf-8') as f:
        misp_config = json.loads(f.read())
    misp_url = misp_config['MISP_url']
    misp_key = misp_config['MISP_automation_key']
    misp_verifycert = misp_config['verify_certificate']
    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
    except Exception as e:
        print(f'Error while connecting to your MISP instance: {e}\nSaving MISP event in {misp_file}.', file=sys.stderr)
        return


def _write_json_logs(filename, honeypot_name):
    logs = tuple(_csv_to_json(filename, honeypot_name))
    with open(f'{filename}.json', 'wt', encoding='utf-8') as f:
        f.write(json.dumps(logs, indent=4))


def parse_csv(args):
    parsed_files = []
    if args.input is not None:
        with open(_CONFIG_PATH / 'passive_ssh_config.json', 'rt', encoding='utf-8') as f:
            passive_ssh_config = json.loads(f.read())
            passive_ssh_url = passive_ssh_config['passive_ssh_url']
            authentication = (passive_ssh_config['api_user'], passive_ssh_config['api_key'])
        for filename in args.input:
            filename = Path(filename).resolve()
            status_code = _perform_queries(filename, args.name, passive_ssh_url, authentication)
            parsed_files.append(f'{filename}.json')
            if status_code == 401:
                _clean_tmp_files(args.savejson, parsed_files)
                sys.exit('Authentication error, please check your config file.', file=sys.stderr)
            if status_code == 404:
                _clean_tmp_files(args.savejson, parsed_files)
                sys.exit()
            if status_code == 0:
                print(f'No Passive-SSH record found for the SSH logs from {filename}')
            else:
                print(f"Passive-SSH records from {filename} successfully saved in {filename}.passivessh.json")
    else:
        for filename in args.passivessh_input:
            csv_filename = filename[:-16]
            _write_json_logs(csv_filename, args.name)
            parsed_files.append(f'{csv_filename}.json')
    if args.misp:
        _push_misp_data(parsed_files)
    _clean_tmp_files(args.savejson, parsed_files)


def parse_pcap(args):
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform lookups on a Passive-SSH platform.')
    subparsers = parser.add_subparsers()

    csv_parser = subparsers.add_parser('csv', help='Parse SSH logs in CSV format.')
    input_parser = csv_parser.add_mutually_exclusive_group(required=True)
    input_parser.add_argument('-i', '--input', nargs='+', help='CSV input file(s).')
    input_parser.add_argument('-p', '--passivessh_input', nargs='+', help='Passive-SSH record already queried input file(s).')
    csv_parser.add_argument('-n', '--name', default='cowrie', help='Honeypot name.')
    csv_parser.add_argument('--misp', action='store_true', help='Submit lookup results to MISP.')
    csv_parser.add_argument('--savejson', action='store_true', help='Save JSON converted data.')
    csv_parser.set_defaults(func=parse_csv)

    pcap_parser = subparsers.add_parser('pcap', parents=[parser], add_help=False, help='Parse SSH packets from pcap file(s).')
    pcap_parser.add_argument('-i', '--input', nargs='+', required=True, help='PCAP input file(s).')
    pcap_parser.add_argument('--misp', action='store_true', help='Submit lookup results to MISP.')
    pcap_parser.set_defaults(func=parse_pcap)

    args = parser.parse_args()
    try:
        args.func(args)
    except argparse.ArgumentError:
        parser.print_help()
        parser.exit()
