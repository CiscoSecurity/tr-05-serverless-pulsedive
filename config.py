import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://pulsedive.com/api/info.php?{query}&key={key}'

    PULSEDIVE_OBSERVABLE_TYPES = {
        'url': 'URL',
        'domain': 'domain',
        'ip': 'ip',
        'ipv6': 'ipv6',
    }

    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }

    PULSEDIVE_API_THREAT_TYPES = {  # ToDo: ask Michael about UI and API Values
        'none': (5, 'Unknown'),
        'unknown': (5, 'Unknown'),
        'low': (3, 'Suspicious'),
        'medium': (3, 'Suspicious'),
        'high': (2, 'Malicious'),
        'critical': (2, 'Malicious'),
    }
