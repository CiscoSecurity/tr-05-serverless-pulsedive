class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        self.code = code or 'unknown'
        self.message = message
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code.lower(),
                'message': self.message}


API_ERRORS_STANDARDISATION = {
    ("Results limited to one page "
     "(15,000 records) for free API."): "resource exhausted",
    "Request(s) still processing.": "request timeout",
    ("API rate limit exceeded: 30 requests per minute. "
     "Requests disabled for 1 minute. Please visit "
     "pulsedive.com/api to increase your limit."): "too many requests"
}


class UnexpectedPulsediveError(TRFormattedError):
    def __init__(self, message):
        code = API_ERRORS_STANDARDISATION.get(message)
        super().__init__(code, message)


class JwtError(TRFormattedError):
    def __init__(self, message):
        super().__init__('permission denied', message)


class StandardHttpError(TRFormattedError):
    def __init__(self, response):
        super().__init__(
            response.reason,
            'The Pulsedive API error.'
        )


class InvalidInputError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            "invalid argument",
            f'Invalid JSON payload received. {message}'
        )


class PulsediveKeyError(TRFormattedError):
    def __init__(self):

        super().__init__(
            code='key error',
            message='The data structure of Pulsedive API has changed.'
                    ' The module is broken.'
        )
