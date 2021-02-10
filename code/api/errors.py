from json.decoder import JSONDecodeError

AUTH_ERROR = 'authorization error'


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


class UnexpectedPulsediveError(TRFormattedError):
    def __init__(self, response):
        code = response.reason
        try:
            message = response.json().get('error')
        except JSONDecodeError:
            message = 'The Pulsedive API error.'
        super().__init__(code, message)


class AuthorizationError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            AUTH_ERROR,
            f'Authorization failed: {message}'
        )


class InvalidInputError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            'invalid argument',
            f'Invalid JSON payload received. {message}'
        )


class PulsediveKeyError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='key error',
            message='The data structure of Pulsedive API has changed.'
                    ' The module is broken.'
        )


class PulsediveSSLError(TRFormattedError):
    def __init__(self, error):
        error = error.args[0].reason.args[0]
        reason = getattr(error, 'verify_message', error.args[0]).capitalize()
        super().__init__(
            code='unknown',
            message=f'Unable to verify SSL certificate: {reason}'
        )


class PulsediveWatchdogError(TRFormattedError):
    def __init__(self):
        super().__init__(
            code='health check failed',
            message='Invalid Health Check'
        )
