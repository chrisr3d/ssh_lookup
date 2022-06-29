import argparse
import json
import requests
import subprocess
import sys
from pathlib import Path
from pymisp import MISPAttribute, MISPEvent, MISPObject, PyMISP
from utils import _create_misp_passive_ssh_object, _import_misp_config, _import_passivessh_config, _set_misp_event_info

_CONNECTION_OBJECT_MAPPING = (
    {'type': 'ip-src', 'object_relation': 'ip-src'},
    {'type': 'port', 'object_relation': 'src-port'},
    {'type': 'ip-dst', 'object_relation': 'ip-dst'},
    {'type': 'port', 'object_relation': 'dst-port'}
)


def parse_pcaps(args):
    first_seen = float('inf')
    last_seen = 0
    misp_event = MISPEvent()
    passivessh_url, authentication = _import_passivessh_config()
    connections = {}
    hasshs = {}
    ips = set()
    passive_ssh = {}
    filters = f"-Y {'ssh.kex.hassh' if args.handshakeonly else 'ssh'} -o tcp.relative_sequence_numbers:FALSE"
    tshark = f'tshark -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssh.kex.hassh {filters} -r'
    cmd = 'parallel --line-buffer --gnu %s {} ::: %s' % (tshark, args.pcapinput)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        timestamp, src_ip, src_port, dst_ip, dst_port, hassh = line.decode().strip('\n').split('\t')
        ips.update([src_ip, dst_ip])
        key = (src_ip, src_port, dst_ip, dst_port)
        if key not in connections:
            connections[key] = {
                'first_seen': float('inf'),
                'counter': 0
            }
        timestamp = float(timestamp)
        if timestamp < connections[key]['first_seen']:
            connections[key]['first_seen'] = timestamp
        if timestamp > last_seen:
            last_seen = timestamp
        if timestamp < first_seen:
            first_seen = timestamp
        connections[key]['counter'] += 1
        if hassh:
            if hassh not in hasshs:
                attribute = MISPAttribute()
                attribute.from_dict(
                    **{
                        'type': 'hassh-md5',
                        'value': hassh
                    }
                )
                hasshs[hassh] = attribute.uuid
                misp_event.add_attribute(**attribute)
                query = requests.get(f'{passivessh_url}/hassh/hosts/{hassh}', auth=authentication)
                if query.status_code == 200:
                    result = query.json()
                    if result['hosts'] or result['kexs']:
                        misp_object = _create_misp_passive_ssh_object(query.json(), hassh=hassh)
                        misp_object.add_reference(attribute.uuid, 'related-to')
                        misp_event.add_object(misp_object)
                        passive_ssh[hassh] = misp_object.uuid
            if 'hassh' in connections[key]:
                connections[key]['hassh'].add(hassh)
            else:
                connections[key]['hassh'] = {hassh}
    misp_event.info = _set_misp_event_info('packets', first_seen, last_seen)
    for ip in ips:
        query = requests.get(f'{passivessh_url}/host/ssh/{ip}', auth=authentication)
        if query.status_code == 200:
            result = query.json()
            if result['hassh'] or result['keys'] or result['banner']:
                misp_object = _create_misp_passive_ssh_object(result, ip_address=ip)
                misp_event.add_object(misp_object)
                passive_ssh[ip] = misp_object.uuid
    for connection, values in connections.items():
        misp_object = MISPObject('network-connection')
        for value, mapping in zip(connection, _CONNECTION_OBJECT_MAPPING):
            attribute = {'value': value}
            attribute.update(mapping)
            misp_object.add_attribute(**attribute)
        misp_object.add_attribute(
            **{
                'type': 'datetime',
                'object_relation': 'first-packet-seen',
                'value': values['first_seen']
            }
        )
        misp_object.add_attribute(
            **{
                'type': 'counter',
                'object_relation': 'count',
                'value': values['counter']
            }
        )
        misp_object.add_attribute(
            **{
                'type': 'text',
                'object_relation': 'layer7-protocol',
                'value': 'SSH'
            }
        )
        for ip_address in connection[::2]:
            if ip_address in passive_ssh:
                misp_object.add_reference(passive_ssh[ip_address], 'characterized-by')
        if 'hassh' in values:
            for hassh in values['hassh']:
                misp_object.add_reference(hasshs[hassh], 'fingerprinted-by')
                if hassh in passive_ssh:
                    misp_object.add_reference(passive_ssh[hassh], 'characterized-by')
        misp_event.add_object(misp_object)
    if args.savejson:
        output_path = Path(args.outputpath) if args.outputpath is not None else Path(__file__).resolve().parent / 'tmp'
        filename = misp_event.info.replace(' ', '_').replace(':', '-')
        with open(output_path / f'{filename}json', 'wt', encoding='utf-8') as f:
            f.write(misp_event.to_json(indent=4))
        print(f'MISP standard format with the results of the parsed PCAP data has been stored in {output_path}/{filename}json')
    if args.pushmisp:
        misp_url, misp_key, misp_verifycert = _import_misp_config()
        try:
            misp = PyMISP(misp_url, misp_key, misp_verifycert)
        except Exception as e:
            print(f'Error while connecting to your MISP instance: {e}')
            return
        misp.add_event(misp_event)


def push_misp_format(args):
    misp_url, misp_key, misp_verifycert = _import_misp_config()
    try:
        misp = PyMISP(misp_url, misp_key, misp_verifycert)
    except Exception as e:
        print(f'Error while connecting to your MISP instance: {e}')
        return
    for filename in args.mispinput:
        try:
            misp_event = MISPEvent()
            misp_event.load_file(filename)
        except Exception as e:
            print(f'Error while loading {filename}: {e}')
            continue
        misp.add_event(misp_event)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform lookups on a Passive-SSH platform with data from PCAP files.')

    input_parser = parser.add_mutually_exclusive_group(required=True)
    input_parser.add_argument('-p', '--pcapinput', type=str, help='PCAP input file(s). (USE QUOTES when giving a glob)')
    input_parser.add_argument('-m', '--mispinput', nargs='+', help='MISP input files(s). (MISP format generated from a previous PCAP files parsing)')

    parser.add_argument('--pushmisp', action='store_true', help='Submit results to MISP.')
    parser.add_argument('--savejson', action='store_true', help='Save results of the PCAP parsing & lookups as MISP standard JSON format')
    parser.add_argument('--handshakeonly', action='store_true', help='Filter to parse only the Handshake packets.')
    parser.add_argument('-o', '--outputpath', help='Output path to store MISP JSON format results.')

    args = parser.parse_args()
    if not args.savejson and not args.pushmisp:
        print('Please use at least one of the following argument:\n  --savejson\n  --pushmisp')
        parser.print_help()
        sys.exit()
    if args.mispinput is not None and not args.pushmisp:
        print('You specified MISP format input files with no argument to push them into MISP, this will not do anything then.')
        parser.print_help()
        sys.exit()
    try:
        if args.pcapinput is not None:
            parse_pcaps(args)
        else:
            push_misp_format(args)
    except argparse.ArgumentError:
        parser.print_help()
        parser.exit()
