from flask import current_app


class TRFormattedError(Exception):
    def __init__(self, code, message):
        self.code = code
        self.message = message


class JwtError(TRFormattedError):
    def __init__(self, message):
        super().__init__('permission denied', message)


class UnexpectedPulsediveError(TRFormattedError):
    def __init__(self, message):
        code = current_app.config['API_ERRORS_STANDARDISATION'] \
            .get(message, 'unknown')
        super().__init__(code, message)


class StandardHttpError(TRFormattedError):
    def __init__(self, code):
        super().__init__(code, 'The Pulsedive API error.')


class InvalidInputError(TRFormattedError):
    def __init__(self, message):
        super().__init__("invalid argument", message)
