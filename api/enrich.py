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


STORAGE_PERIOD = timedelta(days=3*365/12)

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


def time_to_ctr_format(time):
    return time.isoformat() + 'Z'


def get_valid_time(output):
    start_time = datetime.strptime(output['stamp_seen'],
                                   '%Y-%m-%d %H:%M:%S')

    if output['stamp_retired']:
        end_time = datetime.strptime(output['stamp_retired'],
                                     '%Y-%m-%d %H:%M:%S')
    else:
        end_time = start_time + STORAGE_PERIOD

    valid_time = {
        'start_time': time_to_ctr_format(start_time),
        'end_time': time_to_ctr_format(end_time),
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
            query=f"indicator/?iid={output['iid']}"),
        **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
    }

    return doc


def extract_indicators(output, unique_ids):
    docs = []

    if output.get('riskfactors'):
        for riskfactor in output['riskfactors']:
            if riskfactor['rfid'] not in unique_ids['riskfactors'].keys():
                generated_id = f'transient:{uuid4()}'
                unique_ids['riskfactors'][riskfactor['rfid']] = generated_id
                doc = {
                    'id': generated_id,
                    'valid_time': get_valid_time(output),
                    'short_description': riskfactor['description'],
                    'producer': 'Pulsedive',
                    **current_app.config['CTIM_INDICATOR_DEFAULTS']
                }
                docs.append(doc)

    if output.get('threats'):
        for threat in output['threats']:
            if threat['tid'] not in unique_ids['threats'].keys():
                generated_id = f'transient:{uuid4()}'
                unique_ids['threats'][threat['tid']] = generated_id
                score = output['risk']

                type_mapping = \
                    current_app.config["PULSEDIVE_API_THREAT_TYPES"][score]

                start_time = datetime.strptime(threat['stamp_linked'],
                                               '%Y-%m-%d %H:%M:%S')

                doc = {
                    'id': generated_id,
                    'short_description': threat['name'],
                    'producer': 'Pulsedive',
                    'valid_time': {
                        'start_time': time_to_ctr_format(start_time)
                    },
                    'tags': [threat['category']],
                    'severity': type_mapping['severity'],
                    'source_uri': current_app.config['UI_URL'].format(
                        query=f"threat/?tid={threat['tid']}"),
                    **current_app.config['CTIM_INDICATOR_DEFAULTS']
                }
                docs.append(doc)

    if output.get('feeds'):
        for feed in output['feeds']:
            if feed['fid'] not in unique_ids['feeds'].keys():
                generated_id = f'transient:{uuid4()}'
                unique_ids['feeds'][feed['fid']] = generated_id
                start_time = datetime.strptime(feed['stamp_linked'],
                                               '%Y-%m-%d %H:%M:%S')
                doc = {
                    'id': generated_id,
                    'valid_time': {
                        'start_time': time_to_ctr_format(start_time)
                    },
                    'short_description': feed['name'],
                    'producer': feed['organization'],
                    'tags': [feed['category']],
                    'source_uri': current_app.config['UI_URL'].format(
                        query=f"feed/?fid={feed['fid']}"),
                    **current_app.config['CTIM_INDICATOR_DEFAULTS']
                }
                docs.append(doc)

    return docs


def get_relationship(source_ref, target_ref, relationship_type):
    return {
            'source_ref': source_ref,
            'target_ref': target_ref,
            'relationship_type': relationship_type,
            }


def get_related_ips(observable, ips):
    relations = []
    if ips:
        if type(ips) != list:
            ips = [ips]

        for ip in ips:
            relations.append(
                {
                            'origin': 'Pulsedive Enrichment Module',
                            'related': {'type': 'ip', 'value': ip},
                            'relation': 'Resolved_To',
                            'source': observable,
                }
            )
    return relations


def extract_sightings(output, unique_indicator_ids, sightings_relationship):
    docs = []

    observable = {
        'value': output['indicator'],
        'type': output['type']
    }

    score = output['risk']

    if output['retired'] and score == 'none':
        score = 'retired'

    type_mapping = \
        current_app.config["PULSEDIVE_API_THREAT_TYPES"][score]

    related_ips = get_related_ips(
        observable,
        output['properties'].get('dns', {}).get('A')
    )

    if output.get('riskfactors'):
        for riskfactor in output['riskfactors']:

            start_time = datetime.strptime(output['stamp_seen'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:{uuid4()}'
            ind_id = unique_indicator_ids['riskfactors'][riskfactor['rfid']]
            sightings_relationship.append(
                get_relationship(generated_id, ind_id, 'sighting-of')
            )

            doc = {
                'id': generated_id,
                'count': len(output['riskfactors']),
                'observables': [observable],
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'description': riskfactor['description'],
                'severity': type_mapping['severity'],
                'relations': related_ips,
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"indicator/?iid={output['iid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }

            docs.append(doc)

    if output.get('threats'):
        for threat in output['threats']:

            start_time = datetime.strptime(threat['stamp_linked'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:{uuid4()}'

            ind_id = unique_indicator_ids['threats'][threat['tid']]
            sightings_relationship.append(
                get_relationship(generated_id, ind_id, 'sighting-of')
            )

            doc = {
                'id': generated_id,
                'count': len(output['threats']),
                'observables': [observable],
                'description': threat['name'],
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'severity': type_mapping['severity'],
                'relations': related_ips,
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"threat/?tid={threat['tid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }
            docs.append(doc)

    if output.get('feeds'):

        for feed in output['feeds']:

            start_time = datetime.strptime(feed['stamp_linked'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:{uuid4()}'

            ind_id = unique_indicator_ids['feeds'][feed['fid']]
            sightings_relationship.append(
                get_relationship(generated_id, ind_id, 'member-of')
            )

            doc = {
                'id': generated_id,
                'count': len(output['feeds']),
                'observables': [observable],
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'description': feed['name'],
                'relations': related_ips,
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"feed/?fid={feed['fid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }
            docs.append(doc)

    return docs


def extract_relationship(sightings_relationship):
    docs = []
    for relation in sightings_relationship:
        doc = {
            'id': f'transient:{uuid4()}',
            **relation,
            **current_app.config['CTIM_RELATIONSHIP_DEFAULTS'],
        }
        docs.append(doc)

    return docs


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
    sightings = []

    unique_indicator_ids = {'riskfactors': {}, 'threats': {}, 'feeds': {}}
    sightings_relationship = []
    for output in pulsedive_outputs:
        verdicts.append(extract_verdict(output))
        judgements.append(extract_judgement(output))
        indicators += extract_indicators(output, unique_indicator_ids)
        sightings += extract_sightings(output,
                                       unique_indicator_ids,
                                       sightings_relationship
                                       )
    relationships = extract_relationship(sightings_relationship)

    relay_output = {}

    if judgements:
        relay_output['judgements'] = format_docs(judgements)
    if verdicts:
        relay_output['verdicts'] = format_docs(verdicts)
    if indicators:
        relay_output['indicators'] = format_docs(indicators)
    if sightings:
        relay_output['sightings'] = format_docs(sightings)
    if relationships:
        relay_output['relationships'] = format_docs(relationships)

    return jsonify_data(relay_output)


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    # Not implemented
    return jsonify_data([])
