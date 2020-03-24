from collections import defaultdict
from functools import partial
from datetime import datetime

from flask import Blueprint, request, current_app
import requests

from api.schemas import ObservableSchema
from api.errors import (InvalidInputError,
                        UnexpectedPulsediveError,
                        StandardHttpError)

from api.utils import (url_for, get_jwt,
                       jsonify_data, get_json)

enrich_api = Blueprint('enrich', __name__)

observables_schema = ObservableSchema(many=True)
get_observables = partial(get_json, schema=ObservableSchema(many=True))


def validate_relay_input():
    relay_input = request.get_json(force=True, silent=True, cache=False)

    error = observables_schema.validate(relay_input) or None
    if error:
        relay_input = None
        raise InvalidInputError(error)

    return relay_input


def group_observables(relay_input):
    # Leave only unique (value, type) pairs grouped by value.

    observables = defaultdict(set)

    for observable in relay_input:
        value = observable['value']
        type = observable['type'].lower()

        # Discard any unsupported type.
        if type in current_app.config['PULSEDIVE_OBSERVABLE_TYPES']:
            observables[value].add(type)

    observables = {
        value: sorted(types)
        for value, types in observables.items()
    }

    return observables


def get_pulsedive_output(observables, key):
    output = []
    for observable in observables:
        url = url_for('info.php',
                      f'indicator={observable}',
                      key)

        response = requests.get(url)

        error = response.json().get('error')
        if error == "Indicator not found.":
            continue

        if error:
            raise UnexpectedPulsediveError(error)
        elif not response.ok:
            raise StandardHttpError(response)

        output.append(response.json())

    return output


def extract_verdicts(outputs, start_time):
    docs = []

    for output in outputs:
        score = output['risk']

        disposition, disposition_name \
            = current_app.config["PULSEDIVE_API_THREAT_TYPES"].get(score)

        valid_time = {  # ToDo: ask Michael about time
            'start_time': start_time.isoformat() + 'Z'
        }

        observable = {
            'value': output['indicator'],
            'type': output['type']
        }

        doc = {
            'observable': observable,
            'disposition': disposition,
            'disposition_name': disposition_name,
            'valid_time': valid_time,
            **current_app.config['CTIM_VERDICT_DEFAULTS']
        }

        docs.append(doc)

    return docs


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = validate_relay_input()

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    key = get_jwt().get('key')
    pulsedive_output = get_pulsedive_output(observables, key)

    time_now = datetime.utcnow()

    verdicts = extract_verdicts(pulsedive_output, time_now)

    relay_output = {}

    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
