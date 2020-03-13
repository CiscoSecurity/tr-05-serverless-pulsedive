import os

from version import VERSION


class Config(object):
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://pulsedive.com/api/'

    API_ERRORS_STANDARDISATION = {
        "Results limited to one page \
        (15,000 records) for free API.": "resource exhausted",
        "Indicator not found.": "not found",
        "Request(s) still processing.": "request timeout",
    }
