import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://pulsedive.com/api/'

    API_ERRORS = {
        "Results limited to one page \
        (15,000 records) for free API.": "resource_exhausted",
        "Indicator not found.": "not_found",
        "Request(s) still processing.": "request_timeout",
    }
