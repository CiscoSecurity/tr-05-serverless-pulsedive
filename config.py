import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://pulsedive.com/api/info.php?{query}&key={key}'

    UI_URL = "https://pulsedive.com/{query}"

    CTIM_SCHEMA_VERSION = '1.0.16'

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    CTR_ENTITIES_LIMIT = \
        int(os.environ.get('CTR_ENTITIES_LIMIT', CTR_DEFAULT_ENTITIES_LIMIT))

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
        'source': 'Pulsedive',
        'confidence': 'Medium',
        'priority': 85,
        'tlp': 'white',
        'schema_version': CTIM_SCHEMA_VERSION,
    }

    CTIM_INDICATOR_DEFAULTS = {
        'type': 'indicator',
        'tlp': 'white',
        'schema_version': CTIM_SCHEMA_VERSION,
    }

    CTIM_SIGHTING_DEFAULTS = {
        'type': 'sighting',
        'source': 'Pulsedive',
        'confidence': 'Medium',
        'schema_version': CTIM_SCHEMA_VERSION,
    }

    CTIM_RELATIONSHIP_DEFAULTS = {
        'type': 'relationship',
        'tlp': 'white',
        'schema_version': CTIM_SCHEMA_VERSION,
    }

    PULSEDIVE_API_THREAT_TYPES = {
      "none": {
        "disposition": 1,
        "disposition_name": "Clean",
        "severity": "None"
      },
      "unknown": {
        "disposition": 5,
        "disposition_name": "Unknown",
        "severity": "Unknown"
      },
      "retired": {
        "disposition": 5,
        "disposition_name": "Unknown",
        "severity": "Unknown"
      },
      "low": {
        "disposition": 3,
        "disposition_name": "Suspicious",
        "severity": "Low"
      },
      "medium": {
        "disposition": 3,
        "disposition_name": "Suspicious",
        "severity": "Medium"
      },
      "high": {
        "disposition": 2,
        "disposition_name": "Malicious",
        "severity": "High"
      },
      "critical": {
        "disposition": 2,
        "disposition_name": "Malicious",
        "severity": "High"
      }
    }
