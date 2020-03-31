from collections import defaultdict
from functools import partial
from datetime import datetime, timedelta
from uuid import uuid4

from flask import Blueprint, current_app
import requests

from api.schemas import ObservableSchema
from api.errors import (
    UnexpectedPulsediveError,
    StandardHttpError
)

from api.utils import (
    url_for, get_jwt,
    jsonify_data, get_json
)

enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


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


def get_pulsedive_output(observables):
    output = []
    key = get_jwt().get('key')

    header = {
        'User-Agent': ('Cisco Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>'),
    }

    for observable in observables:
        url = url_for(f'indicator={observable}',
                      key)

        response = requests.get(url, headers=header)

        error = response.json().get('error')
        if error == "Indicator not found.":
            continue

        if error:
            raise UnexpectedPulsediveError(error)
        elif not response.ok:
            raise StandardHttpError(response)

        output.append(response.json())

    return output


def get_valid_time(output):
    start_time = datetime.strptime(output['stamp_seen'],
                                   '%Y-%m-%d %H:%M:%S')

    if output['stamp_retired']:
        end_time = datetime.strptime(output['stamp_retired'],
                                     '%Y-%m-%d %H:%M:%S')
    else:
        end_time = start_time + timedelta(days=3*365/12)

    valid_time = {
        'start_time': start_time.isoformat() + 'Z',
        'end_time': end_time.isoformat() + 'Z',
                }

    return valid_time


def extract_verdict(output):
    score = output['risk']

    if output['retired'] and score == 'none':
        score = 'retired'

    type_mapping = current_app.config["PULSEDIVE_API_THREAT_TYPES"][score]

    observable = {
        'value': output['indicator'],
        'type': output['type']
    }

    doc = {
        'observable': observable,
        'disposition': type_mapping['disposition'],
        'disposition_name': type_mapping['disposition_name'],
        'valid_time': get_valid_time(output),
        **current_app.config['CTIM_VERDICT_DEFAULTS']
    }

    return doc


def extract_judgement(output):
    score = output['risk']

    if output['retired'] and score == 'none':
        score = 'retired'

    type_mapping = current_app.config["PULSEDIVE_API_THREAT_TYPES"][score]

    observable = {
        'value': output['indicator'],
        'type': output['type']
    }

    judgement_id = f'transient:{uuid4()}'

    doc = {
        'id': judgement_id,
        'observable': observable,
        'disposition': type_mapping['disposition'],
        'disposition_name': type_mapping['disposition_name'],
        'severity': type_mapping['severity'],
        'valid_time': get_valid_time(output),
        'source_uri': current_app.config['UI_URL'].format(
            iid=output['iid']),
        **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
    }

    return doc


def extract_indicator(output):
    doc = {
        'id': f'transient:{uuid4()}',
        'valid_time': get_valid_time(output),
        'source_uri': current_app.config['UI_URL'].format(
            iid=output['iid']),
        **current_app.config['CTIM_INDICATOR_DEFAULTS']
    }

    return doc


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    # Not implemented
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    relay_input = get_observables()

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data({})

    pulsedive_outputs = get_pulsedive_output(observables)

    verdicts = []
    judgements = []
    indicators = []
    for output in pulsedive_outputs:
        verdicts.append(extract_verdict(output))
        judgements.append(extract_judgement(output))
        indicators.append(extract_indicator(output))
    relay_output = {}

    if judgements:
        relay_output['judgements'] = format_docs(judgements)
    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)
    if indicators:
        relay_output['indicators'] = format_docs(indicators)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
