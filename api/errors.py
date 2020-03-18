class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        self.code = code or 'unknown'
        self.message = message
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


API_ERRORS_STANDARDISATION = {
    "Results limited to one page \
    (15,000 records) for free API.": "resource exhausted",
    "Indicator not found.": "not found",
    "Request(s) still processing.": "request timeout",
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
        super().__init__("invalid argument", message)
