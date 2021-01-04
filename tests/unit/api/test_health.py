from http import HTTPStatus
from unittest.mock import MagicMock, patch
from requests.exceptions import SSLError

from pytest import fixture

from .utils import headers
from tests.unit.payloads_for_tests import (
    EXPECTED_PAYLOAD_WITHOUT_JWT,
    EXPECTED_PAYLOAD_REQUEST_TIMEOUT,
    EXPECTED_RESPONSE_SSL_ERROR,
    EXPECTED_PAYLOAD_INVALID_JWT
)


def routes():
    yield "/health"


@fixture(scope="module", params=routes(), ids=lambda route: f"POST {route}")
def route(request):
    return request.param


def test_health_call_without_jwt_failure(
        route, client, pd_api_request, get_pub_key
):
    pd_api_request.side_effect = get_pub_key()
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_WITHOUT_JWT


@fixture(scope="function")
def pd_api_request():
    with patch("requests.get") as mock_request:
        yield mock_request


def pd_api_response(ok):
    mock_response = MagicMock()

    mock_response.ok = ok
    if ok:
        mock_response.status_code = HTTPStatus.OK
        payload = {
            "iid": 19,
            "type": "ip",
            "indicator": "144.76.107.175",
            "risk": "none",
            "risk_recommended": "none",
            "manualrisk": 0,
            "retired": "No recent activity",
            "stamp_added": "2017-09-27 18:11:44",
            "stamp_updated": "2018-03-26 15:44:24",
            "stamp_seen": "2017-09-27 18:11:44",
            "stamp_retired": "2018-03-26 15:44:24",
            "recent": 0,
        }
    else:
        mock_response.status_code = HTTPStatus.REQUEST_TIMEOUT
        mock_response.reason = 'request timeout'
        payload = {
            "error": "Request(s) still processing.",
            "status": "processing",
            "note": "status field is in beta: processing | not found | do...",
            "qid": "110740426",
        }

    mock_response.json = lambda: payload
    return mock_response


def test_health_call_with_invalid_jwt_failure(
        route, client, pd_api_request, invalid_jwt, get_pub_key
):
    pd_api_request.return_value = get_pub_key
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_INVALID_JWT


def test_health_call_success(
        route, client, pd_api_request, valid_jwt, get_pub_key
):
    pd_api_request.side_effect = (get_pub_key,  pd_api_response(ok=True))
    response = client.post(route, headers=headers(valid_jwt))

    expected_payload = {"data": {"status": "ok"}}

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == expected_payload


def test_health_call_failure(
        route, client, pd_api_request, valid_jwt, get_pub_key
):
    pd_api_request.side_effect = (get_pub_key, pd_api_response(ok=False))
    response = client.post(route, headers=headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.get_json() == EXPECTED_PAYLOAD_REQUEST_TIMEOUT


def test_health_call_ssl_error(
        route, client, valid_jwt, pd_api_request, get_pub_key
):
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    pd_api_request.side_effect = (get_pub_key,  SSLError(mock_exception))

    response = client.post(route, headers=headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK

    data = response.get_json()
    assert data == EXPECTED_RESPONSE_SSL_ERROR
