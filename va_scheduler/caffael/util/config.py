import yaml

_config = None


def read_config(config_file):
    with open(config_file, 'r') as f:
        yaml_config = yaml.safe_load(f)
    print(yaml_config)
    return yaml_config


def get_config():
    global _config
    if not _config:
        _config = read_config('caffael.yaml')
    return _config
