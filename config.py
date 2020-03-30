import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://pulsedive.com/api/info.php?{query}&key={key}'

    UI_URL = "https://pulsedive.com/indicator/?iid={iid}"

    PULSEDIVE_OBSERVABLE_TYPES = {
        'url': 'URL',
        'domain': 'domain',
        'ip': 'ip',
        'ipv6': 'ipv6',
    }

    CTIM_VERDICT_DEFAULTS = {
        'type': 'verdict',
    }

    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'schema_version': '1.0.14',
        'source': 'Pulsedive',
        'confidence': 'Medium',
        'priority': 85,
    }

    PULSEDIVE_API_THREAT_TYPES = {
        'none': (1, 'Clean', 'None'),
        'unknown': (5, 'Unknown', 'Unknown'),
        'retired': (5, 'Unknown', 'Unknown'),
        'low': (3, 'Suspicious', 'Low'),
        'medium': (3, 'Suspicious', 'Medium'),
        'high': (2, 'Malicious', 'High'),
        'critical': (2, 'Malicious', 'High'),
    }
