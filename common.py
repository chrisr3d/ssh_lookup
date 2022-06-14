import json
from pathlib import Path

_CONFIG_PATH = Path(__file__).resolve().parent / 'config'


def import_misp_config():
    with open(_CONFIG_PATH / 'misp_config.json', 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    misp_url = config['MISP_url']
    misp_key = config['MISP_automation_key']
    misp_verifycert = config['verify_certificate']
    return misp_url, misp_key, misp_verifycert


def import_passivessh_config():
    with open(_CONFIG_PATH / 'passive_ssh_config.json', 'rt', encoding='utf-8') as f:
        config = json.loads(f.read())
    passive_ssh_url = config['passive_ssh_url']
    authentication = (config['api_user'], config['api_key'])
    return passive_ssh_url, authentication
