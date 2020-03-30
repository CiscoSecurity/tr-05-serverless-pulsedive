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
        'schema_version': '1.0.16',
        'source': 'Pulsedive',
        'confidence': 'Medium',
        'priority': 85,
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
