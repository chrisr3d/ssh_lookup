import json
from datetime import datetime
from pathlib import Path
from pymisp import MISPObject

_CONFIG_PATH = Path(__file__).resolve().parent / 'config'
_PASSIVE_SSH_OBJECT_MAPPING = {
    'banner': {'type': 'text', 'object_relation': 'banner'},
    'first_seen': {'type': 'datetime', 'object_relation': 'first_seen'},
    'hassh': {'type': 'hassh-md5', 'object_relation': 'hassh'},
    'hosts': {'type': 'ip-dst', 'object_relation': 'host'},
    'last_seen': {'type': 'datetime', 'object_relation': 'last_seen'},
    'port': {'type': 'port', 'object_relation': 'port'}
}


def _create_misp_passive_ssh_object(ssh_record, hassh=None, ip_address=None):
    misp_object = MISPObject('passive-ssh')
    if hassh is not None:
        misp_object.add_attribute(
            **{
                'type': 'hassh-md5',
                'object_relation': 'hassh',
                'value': hassh
            }
        )
    if ip_address is not None:
        misp_object.add_attribute(
            **{
                'type': 'ip-dst',
                'object_relation': 'host',
                'value': ip_address
            }
        )
    if 'keys' in ssh_record:
        for key in ssh_record['keys']:
            misp_object.add_attribute(
                **{
                    'type': 'ssh-fingerprint',
                    'object_relation': 'fingerprint',
                    'value': key['fingerprint']
                }
            )
    for feature in ('hosts', 'hassh', 'banner'):
        if feature in ssh_record:
            values = ssh_record[feature]
            if isinstance(values, str):
                attribute = {'value': values}
                attribute.update(_PASSIVE_SSH_OBJECT_MAPPING[feature])
                misp_object.add_attribute(**attribute)
            else:
                mapping = _PASSIVE_SSH_OBJECT_MAPPING[feature]
                for value in values:
                    attribute = {'value': value}
                    attribute.update(mapping)
                    misp_object.add_attribute(**attribute)
    for feature in ('port', 'first_seen', 'last_seen'):
        if feature in ssh_record:
            attribute = {'value': ssh_record['value']}
            attribute.update(_PASSIVE_SSH_OBJECT_MAPPING[feature])
            misp_object.add_attribute(**attribute)
    return misp_object


def _import_misp_config():
    with open(_CONFIG_PATH / 'misp_config.json', 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    misp_url = config['MISP_url']
    misp_key = config['MISP_automation_key']
    misp_verifycert = config['verify_certificate']
    return misp_url, misp_key, misp_verifycert


def _import_passivessh_config():
    with open(_CONFIG_PATH / 'passive_ssh_config.json', 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    passive_ssh_url = config['passive_ssh_url']
    authentication = (config['api_user'], config['api_key'])
    return passive_ssh_url, authentication


def _set_misp_event_info(feature, first_seen, last_seen):
    first_seen = _timestamp_to_str(first_seen)
    last_seen = _timestamp_to_str(last_seen)
    return f'SSH {feature} captured between {first_seen} and {last_seen}.'


def _timestamp_to_str(timestamp):
    return datetime.strftime(datetime.utcfromtimestamp(int(timestamp)), '%Y-%m-%dT%H:%M:%S')
