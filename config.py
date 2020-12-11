import os
from http import HTTPStatus
from uuid import NAMESPACE_X500

from __version__ import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', None)

    API_URL = 'https://pulsedive.com/api/info.php'

    UI_URL = "https://pulsedive.com/{query}"

    BROWSE_URL = "https://pulsedive.com/browse/?q="

    BROWSE_QUERY = '{{"type":["artifact", "domain","ip","ipv6","url"],' \
                   '"risk":["unknown","none","low","medium","high",' \
                   '"critical","retired"],"lastseen":["all"],"indicator":' \
                   '[{{"raw":{{"type":"indicator","value":' \
                   '"{observable}"}}, "htmlsafe":{{"type":' \
                   '"indicator","value":"{observable}"}},' \
                   '"exact":true}}],"attribute":[],"property"' \
                   ':[],"threat":[], "feed":[]}}'

    CTIM_SCHEMA_VERSION = '1.0.17'

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT

    PULSEDIVE_OBSERVABLE_TYPES = {
        'url': 'URL',
        'domain': 'domain',
        'ip': 'IP',
        'ipv6': 'IPv6',
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
        'source': 'Pulsedive',
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

    OBSERVED_RELATIONS_DEFAULTS = {
        'origin': 'Pulsedive Enrichment Module',
        'relation': 'Resolved_To',
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

    NOT_CRITICAL_ERRORS = (
        HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND, HTTPStatus.NOT_ACCEPTABLE
    )

    NAMESPACE_BASE = NAMESPACE_X500

    USER_AGENT = ('SecureX Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
