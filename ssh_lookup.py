import argparse
import csv
import json
import os
import requests
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from pymisp import PyMISP, MISPEvent, MISPObject

_CONFIG_PATH = Path(__file__).resolve().parent / 'config'
_CONNECTION_OBJECT_FIELDS = ('dst_ip', 'dst_port', 'src_ip', 'src_port', 'timestamp')
_CONNECTION_OBJECT_MAPPING = {
    'dst_port': {'type': 'port', 'object_relation': 'dst-port'},
    'src_ip': {'type': 'ip-src', 'object_relation': 'ip-src'},
    'src_port': {'type': 'port', 'object_relation': 'src-port'}
}
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


def _parse_destination(destination):
    if ':' not in destination and any(letter.isalpha() for letter in destination):
        return {'type': 'hostname', 'object_relation': 'hostname-dst'}
    return {'type': 'ip-dst', 'object_relation': 'ip-dst'}


def _parse_input_args(args):
    if args.csvinput is not None:
        return args.csvinput, _perform_csv_queries, [args.name]
    return args.jsoninput, _perform_json_queries, []


def _parse_status_code(filename, parsed_files, status_code, savejson):
    if status_code == 401:
        _clean_tmp_files(savejson, parsed_files)
        sys.exit('Authentication error, please check your config file.', file=sys.stderr)
    if status_code == 404:
        _clean_tmp_files(savejson, parsed_files)
        sys.exit()
    if status_code == 0:
        print(f'No Passive-SSH record found for the SSH logs from {filename}')
    else:
        print(f"Passive-SSH records from {filename} successfully saved in {filename}.passivessh.json")


def _perform_csv_queries(filename, honeypot_name, passive_ssh_url, authentication):
    ssh_logs = tuple(_csv_to_json(filename, honeypot_name))
    _write_json_logs(filename, honeypot_name)
    return _perform_queries(ssh_logs, filename, passive_ssh_url, authentication)


def _perform_json_queries(filename, passive_ssh_url, authentication):
    with open(filename, 'rt', encoding='utf-8') as f:
        ssh_logs = json.loads(f.read())
    _perform_queries(ssh_logs, filename, passive_ssh_url, authentication)


def _perform_queries(ssh_logs, filename, passive_ssh_url, authentication):
    ip_addresses = {log['src_ip'] for log in ssh_logs}
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


def _push_misp_data(parsed_files, feature):
    first_seen = float('inf')
    last_seen = 0
    misp_event = MISPEvent()
    connections = defaultdict(list)
    passive_ssh_records = {}
    for filename in parsed_files:
        with open(filename, 'rt', encoding='utf-8') as f:
            ssh_logs = json.loads(f.read())
        for log in ssh_logs:
            if 'dst_ip' in log:
                connections[log['src_ip']].append(
                    {key: value for key, value in log.items() if key in _CONNECTION_OBJECT_FIELDS}
                )
        try:
            passive_name = filename if feature == 'json' else filename[:-5]
            with open(f'{passive_name}.passivessh.json', 'rt', encoding='utf-8') as f:
                passivessh_record = json.loads(f.read())
        except FileNotFoundError:
            print(f'Error loading the Passive-SSH records file: {filename[:-5]}.passivessh.json', file=sys.stderr)
            continue
        for ip_address, record in passivessh_record.items():
            passive_ssh_records[ip_address] = record
    for ip_address, network_connections in connections.items():
        connection_uuids = []
        for network_connection in network_connections:
            connection_object = MISPObject('network-connection')
            dst_ip = network_connection['dst_ip']
            attribute = _parse_destination(dst_ip)
            attribute['value'] = dst_ip
            connection_object.add_attribute(**attribute)
            for feature, attribute in _CONNECTION_OBJECT_MAPPING.items():
                if feature in network_connection:
                    misp_attribute = {'value': network_connection[feature].replace(',', '')}
                    misp_attribute.update(attribute)
                    connection_object.add_attribute(**misp_attribute)
            connection_object.add_attribute(
                **{
                    'type': 'datetime',
                    'object_relation': 'first-packet-seen',
                    'value': network_connection['timestamp']
                }
            )
            timestamp = _date_to_timestamp(network_connection['timestamp'])
            if timestamp > last_seen:
                last_seen = timestamp
            if timestamp < first_seen:
                first_seen = timestamp
            connection_object.add_attribute(
                **{
                    'type': 'text',
                    'object_relation': 'layer7-protocol',
                    'value': 'SSH'
                }
            )
            misp_event.add_object(connection_object)
            connection_uuids.append(connection_object.uuid)
        if ip_address in passive_ssh_records:
            record = passive_ssh_records[ip_address]
            passive_ssh = MISPObject('passive-ssh')
            passive_ssh.add_attribute(
                **{
                    'type': 'ip-dst',
                    'object_relation': 'host',
                    'value': ip_address
                }
            )
            if 'keys' in record:
                for key in record['keys']:
                    passive_ssh.add_attribute(
                        **{
                            'type': 'ssh-fingerprint',
                            'object_relation': 'fingerprint',
                            'value': key['fingerprint']
                        }
                    )
            if 'hassh' in record:
                for hassh in record['hassh']:
                    passive_ssh.add_attribute(
                        **{
                            'type': 'hassh-md5',
                            'object_relation': 'hassh',
                            'value': hassh
                        }
                    )
            for feature in ('first_seen', 'last_seen'):
                passive_ssh.add_attribute(
                    **{
                        'type': 'datetime',
                        'object_relation': feature,
                        'value': record[feature]
                    }
                )
            for connection_uuid in connection_uuids:
                passive_ssh.add_reference(connection_uuid, 'related-to')
            misp_event.add_object(passive_ssh)
    with open(_CONFIG_PATH / 'misp_config.json', 'rt', encoding='utf-8') as f:
        misp_config = json.loads(f.read())
    misp_url = misp_config['MISP_url']
    misp_key = misp_config['MISP_automation_key']
    misp_verifycert = misp_config['verify_certificate']
    first_seen = _timestamp_to_str(first_seen)
    last_seen = _timestamp_to_str(last_seen)
    misp_event.info = f'SSH logs captured between {first_seen} and {last_seen}'
    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
    except Exception as e:
        import uuid
        misp_file = Path(__file__).resolve().parent / 'tmp' / f'{uuid.uuid4()}.json'
        with open(misp_file, 'wt', encoding='utf-8') as f:
            f.write(misp_event.to_json(indent=4))
        print(f'Error while connecting to your MISP instance: {e}\nSaving MISP event in {misp_file}.', file=sys.stderr)
        return
    misp.add_event(misp_event)



def _date_to_timestamp(date):
    for ordinal in ('th', 'st', 'rd'):
        if ordinal in date:
            break
    return datetime.strptime(date, f'%B %d{ordinal} %Y, %H:%M:%S.%f').timestamp()


def _timestamp_to_str(timestamp):
    return datetime.strftime(datetime.utcfromtimestamp(int(timestamp)), '%Y-%m-%d %H:%M:%S')


def _write_json_logs(ssh_logs, filename):
    with open(f'{filename}.json', 'wt', encoding='utf-8') as f:
        f.write(json.dumps(ssh_logs, indent=4))


def parse_logs(args):
    parsed_files = []
    if args.passivessh_input is not None:
        feature = 'pcap'
        for filename in args.passivessh_input:
            csv_filename = filename[:-16]
            ssh_logs = tuple(_csv_to_json(filename, args.name))
            _write_json_logs(ssh_logs, csv_filename)
            parsed_files.append(f'{csv_filename}.json')
    else:
        with open(_CONFIG_PATH / 'passive_ssh_config.json', 'rt', encoding='utf-8') as f:
            passive_ssh_config = json.loads(f.read())
            passive_ssh_url = passive_ssh_config['passive_ssh_url']
            authentication = (passive_ssh_config['api_user'], passive_ssh_config['api_key'])
        if args.csvinput is not None:
            feature = 'csv'
            for filename in args.csvinput:
                filename = Path(filename).resolve()
                status_code = _perform_csv_queries(filename, args.name, passive_ssh_url, authentication)
                parsed_files.append(f"{filename}.json")
                _parse_status_code(filename, parsed_files, status_code, args.savejson)
        else:
            feature = 'json'
            for filename in args.jsoninput:
                filename = Path(filename).resolve()
                status_code = _perform_json_queries(filename, passive_ssh_url, authentication)
                parsed_files.append(filename)
                _parse_status_code(filename, parsed_files, status_code, args.savejson)
    if args.misp:
        _push_misp_data(parsed_files, feature)
    _clean_tmp_files(args.savejson, parsed_files)


def parse_pcap(args):
    return


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform lookups on a Passive-SSH platform.')
    subparsers = parser.add_subparsers()

    logs_parser = subparsers.add_parser('logs', help='Parse SSH logs in CSV format.')
    input_parser = logs_parser.add_mutually_exclusive_group(required=True)
    input_parser.add_argument('-c', '--csvinput', nargs='+', help='CSV input file(s).')
    input_parser.add_argument('-j', '--jsoninput', nargs='+', help='JSON input file(s).')
    input_parser.add_argument('-p', '--passivessh_input', nargs='+', help='Passive-SSH record already queried input file(s).')
    logs_parser.add_argument('-n', '--name', default='cowrie', help='Honeypot name.')
    logs_parser.add_argument('--misp', action='store_true', help='Submit lookup results to MISP.')
    logs_parser.add_argument('--savejson', action='store_true', help='Save JSON converted data.')
    logs_parser.set_defaults(func=parse_logs)

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
