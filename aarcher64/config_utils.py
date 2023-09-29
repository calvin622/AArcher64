import configparser
from collections import namedtuple

def load_config():
    Config = namedtuple('Config', [
        'gadget_search_amount',
        'instruction_count',
        'allow_sp_change',
        'return_controllable',
        'controllable_registers',
        'enable_contraint_finding'
     
    ])
    config_parser = configparser.ConfigParser()
    config_parser.read('/home/ubuntu/AArcher64/aarcher64/config.ini')
    return Config(
        gadget_search_amount=int(config_parser['Settings']['gadget_search_amount']),
        instruction_count=int(config_parser['Settings']['instruction_count']),
        allow_sp_change=config_parser.getboolean('Settings', 'allow_sp_change'),
        return_controllable=config_parser.getboolean('Settings', 'return_controllable'),
        controllable_registers=config_parser.getboolean('Settings', 'controllable_registers'),
        enable_contraint_finding=config_parser.getboolean('Settings', 'enable_contraint_finding')
    
    )