import traceback

from flask import Flask, jsonify, g

from api.enrich import enrich_api
from api.health import health_api
from api.watchdog import watchdog_api
from api.version import version_api

from api.errors import TRFormattedError
from api.utils import jsonify_result


app = Flask(__name__)

app.url_map.strict_slashes = False
app.config.from_object('config.Config')

app.register_blueprint(health_api)
app.register_blueprint(enrich_api)
app.register_blueprint(watchdog_api)
app.register_blueprint(version_api)


@app.errorhandler(Exception)
def handle_error(exception):
    app.logger.error(traceback.format_exc())
    code = getattr(exception, 'code', 500)
    message = getattr(exception, 'description', 'Something went wrong.')
    reason = '.'.join([
        exception.__class__.__module__,
        exception.__class__.__name__,
    ])

    response = jsonify(code=code, message=message, reason=reason)
    return response, code


@app.errorhandler(TRFormattedError)
def handle_pusledive_errors(error):
    app.logger.error(traceback.format_exc())
    g.errors = [error.json]
    return jsonify_result()


if __name__ == '__main__':
    app.run()
