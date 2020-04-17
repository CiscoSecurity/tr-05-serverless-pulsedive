from http import HTTPStatus
from unittest import mock

from pytest import fixture

from .utils import headers
from tests.unit.payloads_for_tests import (
    EXPECTED_PAYLOAD_INVALID_INPUT,
    EXPECTED_PAYLOAD_FORBIDDEN,
    EXPECTED_PAYLOAD_OBSERVE,
    EXPECTED_PAYLOAD_OBSERVE_WITH_LIMIT,
    EXPECTED_PAYLOAD_REQUEST_TIMOUT,
    EXPECTED_PAYLOAD_REFER,
    PULSEDIVE_RESPONSE_MOCK,
    PULSEDIVE_REQUEST_TIMOUT,
)


def routes():
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


@fixture(scope='function')
def pd_api_request():
    with mock.patch('requests.get') as mock_request:
        yield mock_request


def pd_api_response(*, ok):
    mock_response = mock.MagicMock()

    mock_response.ok = ok

    if ok:
        payload = PULSEDIVE_RESPONSE_MOCK

    else:
        payload = PULSEDIVE_REQUEST_TIMOUT

    mock_response.json = lambda: payload

    return mock_response


@fixture(scope='module')
def expected_payload(any_route):
    payload = None

    if any_route.startswith('/deliberate'):
        payload = {}

    if any_route.startswith('/observe'):
        payload = EXPECTED_PAYLOAD_OBSERVE

    if any_route.startswith('/refer'):
        payload = EXPECTED_PAYLOAD_REFER

    return payload


def test_enrich_call_with_invalid_jwt_failure(route,
                                              client,
                                              invalid_jwt,
                                              valid_json):

    response = client.post(route,
                           headers=headers(invalid_jwt),
                           json=valid_json)
    assert response.get_json() == EXPECTED_PAYLOAD_FORBIDDEN


def all_routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module',
         params=all_routes(),
         ids=lambda route: f'POST {route}')
def any_route(request):
    return request.param


def test_enrich_call_without_jwt_success(any_route,
                                         client,
                                         valid_json,
                                         pd_api_request,
                                         expected_payload):

    if any_route.startswith('/observe'):
        pd_api_request.return_value = pd_api_response(ok=True)
        response = client.post(any_route, json=valid_json)
        data = response.get_json()

        verdicts = data['data']['verdicts']
        assert verdicts['count'] == 1

        judgements = data['data']['judgements']
        assert judgements['count'] == 1
        assert judgements['docs'][0].pop('id')

        indicators = data['data']['indicators']
        assert indicators['count'] == 5
        indicator_ids = []
        for indicator in indicators['docs']:
            indicator_ids.append(indicator.pop('id'))

        sightings = data['data']['sightings']
        assert sightings['count'] == 5
        sighting_ids = []
        for sighting in sightings['docs']:
            sighting_ids.append(sighting.pop('id'))

        relationships = data['data']['relationships']
        assert relationships['count'] == 5
        for i, relationship in enumerate(relationships['docs']):
            assert relationship.pop('id')
            assert relationship.pop('source_ref') == sighting_ids[i]
            assert relationship.pop('target_ref') == indicator_ids[i]

        assert data == expected_payload
    else:
        response = client.post(any_route)

    assert response.status_code == HTTPStatus.OK

    if any_route.startswith('/refer'):
        pd_api_request.return_value = pd_api_response(ok=True)
        response = client.post(any_route, json=valid_json)

        data = response.get_json()

        assert response.status_code == HTTPStatus.OK
        assert data == expected_payload


def test_enrich_call_without_jwt_but_invalid_json_failure(route,
                                                          client,
                                                          invalid_json):
    response = client.post(route, json=invalid_json)
    assert response.get_json() == EXPECTED_PAYLOAD_INVALID_INPUT


@fixture(scope='module')
def invalid_json():
    return [{'type': 'unknown', 'value': 'https://google.com'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(route,
                                                             client,
                                                             valid_jwt,
                                                             invalid_json):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)
    assert response.get_json() == EXPECTED_PAYLOAD_INVALID_INPUT


def test_enrich_call_success(any_route,
                             client,
                             valid_jwt,
                             valid_json,
                             pd_api_request,
                             expected_payload):
    if any_route.startswith('/observe'):
        pd_api_request.return_value = pd_api_response(ok=True)
        response = client.post(any_route,
                               headers=headers(valid_jwt),
                               json=valid_json)

        data = response.get_json()
        verdicts = data['data']['verdicts']

        assert response.status_code == HTTPStatus.OK
        assert verdicts['count'] == 1

        judgements = data['data']['judgements']
        assert judgements['count'] == 1
        assert judgements['docs'][0].pop('id')

        indicators = data['data']['indicators']
        assert indicators['count'] == 5
        indicator_ids = []
        for indicator in indicators['docs']:
            indicator_ids.append(indicator.pop('id'))

        sightings = data['data']['sightings']
        assert sightings['count'] == 5
        sighting_ids = []
        for sighting in sightings['docs']:
            sighting_ids.append(sighting.pop('id'))

        relationships = data['data']['relationships']
        assert relationships['count'] == 5
        for i, relationship in enumerate(relationships['docs']):
            assert relationship.pop('id')
            assert relationship.pop('source_ref') == sighting_ids[i]
            assert relationship.pop('target_ref') == indicator_ids[i]

        assert data == expected_payload
    else:
        response = client.post(any_route)

        assert response.status_code == HTTPStatus.OK

    if any_route.startswith('/refer'):
        pd_api_request.return_value = pd_api_response(ok=True)
        response = client.post(any_route,
                               headers=headers(valid_jwt),
                               json=valid_json)

        data = response.get_json()

        assert response.status_code == HTTPStatus.OK
        assert data == expected_payload


def test_enrich_call_failure(route,
                             client,
                             valid_jwt,
                             valid_json,
                             pd_api_request):
    pd_api_request.return_value = pd_api_response(ok=False)
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=valid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_REQUEST_TIMOUT


def test_enrich_call_success_limit_1(any_route,
                                     client,
                                     valid_jwt,
                                     valid_json,
                                     pd_api_request):
    if any_route.startswith('/observe'):
        client.application.config['CTR_ENTITIES_LIMIT'] = 1

        pd_api_request.return_value = pd_api_response(ok=True)
        response = client.post(any_route,
                               headers=headers(valid_jwt),
                               json=valid_json)

        data = response.get_json()

        assert response.status_code == HTTPStatus.OK

        verdicts = data['data']['verdicts']
        assert verdicts['count'] == 1

        judgements = data['data']['judgements']
        assert judgements['count'] == 1
        assert judgements['docs'][0].pop('id')

        indicators = data['data']['indicators']
        assert indicators['count'] == 1
        indicator_id = indicators['docs'][0].pop('id')

        sightings = data['data']['sightings']
        assert sightings['count'] == 1
        sighting_id = sightings['docs'][0].pop('id')

        relationships = data['data']['relationships']
        assert relationships['count'] == 1
        assert relationships['docs'][0].pop('id')
        assert relationships['docs'][0].pop('source_ref') == sighting_id
        assert relationships['docs'][0].pop('target_ref') == indicator_id

        assert data == EXPECTED_PAYLOAD_OBSERVE_WITH_LIMIT
    else:
        response = client.post(any_route)

        assert response.status_code == HTTPStatus.OK
