from collections import defaultdict, namedtuple
from functools import partial
from datetime import datetime, timedelta
from uuid import uuid4
from base64 import b64encode
from urllib.parse import quote

from flask import Blueprint, current_app, g
import requests

from api.schemas import ObservableSchema
from api.errors import (
    UnexpectedPulsediveError,
    StandardHttpError
)

from api.utils import (
    get_jwt, jsonify_data, get_json, jsonify_result, key_error_handler
)


STORAGE_PERIOD = timedelta(days=3*365/12)
ACTIVE_DNS_RELEVANCE_PERIOD = timedelta(days=90)

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
            observables[value] = type

    return observables


def sort_entities(list_):
    return list_.sort(
        key=lambda x: x['stamp_linked'], reverse=True
    )


def get_pulsedive_output(observable, links=False):
    output = {}
    key = get_jwt().get('key')

    header = {
        'User-Agent': ('Cisco Threat Response Integrations '
                       '<tr-integrations-support@cisco.com>'),
    }

    url = current_app.config["API_URL"]
    params = {
        'indicator': observable,
        'key': key
    }
    if links:
        params['get'] = 'links'

    response = requests.get(url, headers=header, params=params)

    error = response.json().get('error')

    if error not in (*current_app.config['NOT_CRITICAL_ERRORS'], None):
        raise UnexpectedPulsediveError(error)
    elif not response.ok:
        raise StandardHttpError(response)
    payload = response.json()
    if payload.get('threats'):
        sort_entities(payload['threats'])
    if payload.get('feeds'):
        sort_entities(payload['feeds'])
    output.update(payload)

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


@key_error_handler
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


@key_error_handler
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


def standardize_feed(name):
    return f'Feed: {name.replace("Feed", "")}'


@key_error_handler
def extract_indicators(output, unique_ids):
    docs = []

    if output.get('riskfactors'):
        for riskfactor in output['riskfactors']:
            if riskfactor['rfid'] not in unique_ids['riskfactors'].keys():
                generated_id = f'transient:indicator-{uuid4()}'
                doc = {
                    'id': generated_id,
                    'valid_time': get_valid_time(output),
                    'short_description': riskfactor['description'],
                    'producer': 'Pulsedive',
                    **current_app.config['CTIM_INDICATOR_DEFAULTS']
                }

                if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                    return docs

                unique_ids['riskfactors'][riskfactor['rfid']] = generated_id

                docs.append(doc)

    if output.get('threats'):
        for threat in output['threats']:
            if threat['tid'] not in unique_ids['threats'].keys():
                generated_id = f'transient:indicator-{uuid4()}'
                score = output['risk']

                type_mapping = \
                    current_app.config["PULSEDIVE_API_THREAT_TYPES"][score]

                start_time = datetime.strptime(threat['stamp_linked'],
                                               '%Y-%m-%d %H:%M:%S')

                doc = {
                    'id': generated_id,
                    'short_description': f"Threat: {threat['name']}",
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

                if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                    return docs

                unique_ids['threats'][threat['tid']] = generated_id

                docs.append(doc)

    if output.get('feeds'):
        for feed in output['feeds']:
            if feed['fid'] not in unique_ids['feeds'].keys():
                generated_id = f'transient:indicator-{uuid4()}'

                start_time = datetime.strptime(feed['stamp_linked'],
                                               '%Y-%m-%d %H:%M:%S')
                doc = {
                    'id': generated_id,
                    'valid_time': {
                        'start_time': time_to_ctr_format(start_time)
                    },
                    'short_description': standardize_feed(feed['name']),
                    'producer': feed['organization'],
                    'tags': [feed['category']],
                    'source_uri': current_app.config['UI_URL'].format(
                        query=f"feed/?fid={feed['fid']}"),
                    **current_app.config['CTIM_INDICATOR_DEFAULTS']
                }

                if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                    return docs

                unique_ids['feeds'][feed['fid']] = generated_id

                docs.append(doc)

    return docs


def get_relationship(source_ref, target_ref, relationship_type):
    Relationship = namedtuple(
        'Relationship', ['source_ref', 'target_ref', 'relationship_type']
    )
    return Relationship(
            source_ref=source_ref,
            target_ref=target_ref,
            relationship_type=relationship_type
    )


def is_relevant(time):
    time_linked = datetime.strptime(time, '%Y-%m-%d %H:%M:%S')
    time_now = datetime.utcnow()
    return time_now - time_linked < ACTIVE_DNS_RELEVANCE_PERIOD


def get_related_entities(observable):
    output = get_pulsedive_output(observable['value'], links=True)
    relations = []
    if not output:
        return relations

    entities = output.get('Active DNS')
    if entities:
        if isinstance(entities, str):
            entities = [entities]

        valid_pairs = (('domain', 'ip'), ('ip', 'domain'), ('ipv6', 'domain'))

        for entity in entities:
            if (entity['type'], observable['type']) in valid_pairs\
                    and is_relevant(entity['stamp_linked']):
                if observable['type'] == 'domain':
                    relations.append(
                        {**current_app.config['OBSERVED_RELATIONS_DEFAULTS'],
                         "source": observable,
                         "related": {
                                'type': entity['type'],
                                'value': entity['indicator']
                                }})
                else:
                    relations.append(
                        {**current_app.config['OBSERVED_RELATIONS_DEFAULTS'],
                         "source": {
                                'type': entity['type'],
                                'value': entity['indicator']
                                },
                         "related": observable})
    return relations


@key_error_handler
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

    if output.get('riskfactors'):
        for riskfactor in output['riskfactors']:

            start_time = datetime.strptime(output['stamp_seen'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:sighting-{uuid4()}'

            doc = {
                'id': generated_id,
                'count': 1,
                'observables': [observable],
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'description': riskfactor['description'],
                'severity': type_mapping['severity'],
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"indicator/?iid={output['iid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }

            if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                return docs

            ind_id = unique_indicator_ids['riskfactors'][riskfactor['rfid']]
            sightings_relationship.add(
                get_relationship(generated_id, ind_id, 'sighting-of')
            )

            docs.append(doc)

    if output.get('threats'):
        for threat in output['threats']:

            start_time = datetime.strptime(threat['stamp_linked'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:sighting-{uuid4()}'

            doc = {
                'id': generated_id,
                'count': 1,
                'observables': [observable],
                'description': f"Threat: {threat['name']}",
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'severity': type_mapping['severity'],
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"threat/?tid={threat['tid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }

            if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                return docs

            ind_id = unique_indicator_ids['threats'][threat['tid']]
            sightings_relationship.add(
                get_relationship(generated_id, ind_id, 'sighting-of')
            )

            docs.append(doc)

    if output.get('feeds'):
        for feed in output['feeds']:

            start_time = datetime.strptime(feed['stamp_linked'],
                                           '%Y-%m-%d %H:%M:%S')

            generated_id = f'transient:sighting-{uuid4()}'

            doc = {
                'id': generated_id,
                'count': 1,
                'observables': [observable],
                'observed_time': {
                    'start_time': time_to_ctr_format(start_time)
                },
                'description': standardize_feed(feed['name']),
                'source_uri': current_app.config['UI_URL'].format(
                    query=f"feed/?fid={feed['fid']}"),
                **current_app.config['CTIM_SIGHTING_DEFAULTS']
            }

            if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
                return docs

            ind_id = unique_indicator_ids['feeds'][feed['fid']]
            sightings_relationship.add(
                get_relationship(generated_id, ind_id, 'member-of')
            )

            docs.append(doc)

    relations = get_related_entities(observable)
    if relations:
        start_time = datetime.strptime(output['stamp_seen'],
                                       '%Y-%m-%d %H:%M:%S')

        doc = {
            'id': f'transient:sighting-{uuid4()}',
            'count': 1,
            'observables': [observable],
            'observed_time': {
                'start_time': time_to_ctr_format(start_time)
            },
            'description': 'Active DNS',
            'relations': relations,
            **current_app.config['CTIM_SIGHTING_DEFAULTS'],
            'source_uri': current_app.config['UI_URL'].format(
                query=f"indicator/?iid={output['iid']}"),
        }

        if len(docs) >= current_app.config['CTR_ENTITIES_LIMIT']:
            return docs

        docs.append(doc)

    return docs


def extract_relationship(sightings_relationship):
    docs = []
    for relation in sightings_relationship:
        doc = {
            'id': f'transient:{uuid4()}',
            'source_ref': relation.source_ref,
            'target_ref': relation.target_ref,
            'relationship_type': relation.relationship_type,
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

    g.verdicts = []
    g.judgements = []
    g.indicators = []
    g.sightings = []

    unique_indicator_ids = {'riskfactors': {}, 'threats': {}, 'feeds': {}}
    sightings_relationship = set()
    for value in observables.keys():
        output = get_pulsedive_output(value)
        if not output.get('error'):
            g.verdicts.append(extract_verdict(output))
            g.judgements.append(extract_judgement(output))
            g.indicators += extract_indicators(output, unique_indicator_ids)
            g.sightings += extract_sightings(output,
                                             unique_indicator_ids,
                                             sightings_relationship
                                             )
            g.relationships = extract_relationship(sightings_relationship)

    return jsonify_result()


def get_browse_pivot(observable):
    output = get_pulsedive_output(observable)
    pivots = []

    if not output.get('error'):
        url = current_app.config['UI_URL'].format(
            query=f"indicator/?iid={output['iid']}")
        value = output['indicator']
        type = output['type']
        pivots.append(
            {'id': f'ref-pulsedive-detail'
                   f'-{type}-{quote(value, safe="")}',
             'title':
                 ('Browse '
                  f'{current_app.config["PULSEDIVE_OBSERVABLE_TYPES"][type]}'
                  ),
             'description':
                 ('Browse this '
                  f'{current_app.config["PULSEDIVE_OBSERVABLE_TYPES"][type]}'
                  ' on Pulsedive'
                  ),
             'url': url,
             'categories': ['Browse', 'Pulsedive'],
             }
        )
    return pivots


def encode_str(query, value):
    query = query.format(observable=value)
    return b64encode(query.encode("utf-8")).decode("utf-8")


def get_search_pivots(value, type):
    return {'id': f'ref-pulsedive-search-{type}-{quote(value, safe="")}',
            'title':
                (
                 'Search for this '
                 f'{current_app.config["PULSEDIVE_OBSERVABLE_TYPES"][type]}'
                ),
            'description':
                (
                 'Lookup this '
                 f'{current_app.config["PULSEDIVE_OBSERVABLE_TYPES"][type]} '
                 'on Pulsedive'
                ),
            'url':
                (
                 f'{current_app.config["BROWSE_URL"]}'
                 f'{encode_str(current_app.config["BROWSE_QUERY"], value)}'
                ),
            'categories': ['Search', 'Pulsedive'],
            }


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    relay_input = get_observables()

    observables = group_observables(relay_input)

    if not observables:
        return jsonify_data([])

    relay_output = []

    for value, type in observables.items():
        relay_output.append(get_search_pivots(value, type))
    relay_output += get_browse_pivot(observables)

    return jsonify_data(relay_output)
