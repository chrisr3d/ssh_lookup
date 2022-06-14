import argparse
import json
import requests
import subprocess
import sys
from pymisp import MISPAttribute, MISPEvent, MISPObject
from .common import import_misp_config, import_passivessh_config

_CONNECTION_OBJECT_MAPPING = (
    {'type': 'ip-src', 'object_relation': 'ip-src'},
    {'type': 'port', 'object_relation': 'src-port'},
    {'type': 'ip-dst', 'object_relation': 'ip-dst'},
    {'type': 'port', 'object_relation': 'dst-port'}
)


def parse_pcaps(args):
    passivessh_url, authentication = import_passivessh_config()
    connections = {}
    hasshs = {}
    ips = set()
    passive_ssh = {}
    tshark = f'tshark -T fields -e frame.time_epoch -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e ssh.kex.hassh -Y ssh -o tcp.relative_sequence_numbers:FALSE -r'
    cmd = 'parallel --line-buffer --gnu %s {} ::: %s' % (tshark, args.pcapinput)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        timestamp, src_ip, src_port, dst_ip, dst_port, hassh = line.decode().strip('\n').split('\t')
        ids.update([src_ip, dst_ip])
        key = (src_ip, src_port, dst_ip, dst_port)
        if key not in connections:
            connections[key] = {'first_seen': float('inf')}
        timestamp = float(timestamp)
        if timestamp < connections[key]['first_seen']:
            connections[key]['first_seen'] = timestamp
        if hassh:
            if hassh not in hasshs:
                attribute = MISPAttribute()
                attribute.from_dict(
                    **{
                        'type': 'hassh',
                        'value': hassh
                    }
                )
                hasshs[hassh] = attribute.uuid
                misp_event.add_attribute(**attribute)
                query = requests.get('{passivessh_url}/hassh/hosts/{hassh}', auth=authentication)
                if query.status_code == 200:
                    passive_ssh[hassh] = create_misp_passive_ssh_object(query.json())
            if 'hassh' in connections[key]:
                connections[key]['hassh'].add(hassh)
            else:
                connections[key]['hassh'] = {hassh}
    for ip in ips:
        query = requests.get(f'{passivessh_url}/host/ssh/{ip}', auth=authentication)
        if query.status_code == 200:
            passive_ssh[ip] = create_misp_passive_ssh_object(query.json())
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
                'type': 'text',
                'object_relation': 'layer7-protocol',
                'value': 'SSH'
            }
        )
        if 'hassh' in values:
            for hassh in values['hassh']:
                misp_object.add_reference(hasshs[hassh], 'fingerprinted-by')
        misp_event.add_object(misp_object)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Perform lookups on a Passive-SSH platform with data from PCAP files.')

    input_parser = parser.add_mutually_exclusive_group(required=True)
    input_parser.add_argument('-p', '--pcapinput', type=str, help='PCAP input file(s). (USE QUOTES when giving a glob)')
    input_parser.add_argument('-m', '--mispinput', nargs='+', help='MISP input files(s). (MISP format generated from a previous PCAP files parsing)')

    parser.add_argument('--misp', action='store_true', help='Submit results to MISP.')
    parser.add_argument('-s', '--savejson', action='store_true', help='Save results of the PCAP parsing & lookups as MISP standard JSON format')

    args = parser.parse_args()
    if args.mispinput is not None and not args.misp:
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
