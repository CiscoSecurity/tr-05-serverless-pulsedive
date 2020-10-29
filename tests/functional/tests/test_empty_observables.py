import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import (
    enrich_observe_observables,
    enrich_refer_observables
)
from tests.functional.tests.constants import MODULE_NAME


@pytest.mark.parametrize(
    'observable_type, observable',
    (
     ('url', 'https://www.some.com/'),
     ('ip', '23.23.23.23'),
     ('domain', 'some.me'),
     ('ipv6', '2a51:238:10a:202:1159::'),
     )
)
def test_positive_smoke_empty_observe_observables(module_headers, observable,
                                                  observable_type):
    """Perform testing for enrich observe observables endpoint to check that
     observable, on which Pulsedive doesn't have information, will return empty
     data

    ID: CCTRI-1695-b98d1d01-fd20-492f-bda5-bafb313a0737

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains empty dict from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_pulsedive = get_observables(response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive['module'] == MODULE_NAME
    assert response_from_pulsedive['module_instance_id']
    assert response_from_pulsedive['module_type_id']

    assert response_from_pulsedive['data'] == {}


@pytest.mark.parametrize(
    'observable_type, observable',
    (
     ('url', 'https://www.some.com/'),
     ('ip', '23.23.23.23'),
     ('domain', 'some.me'),
     ('ipv6', '2a51:238:10a:202:1159::'),
     )
)
def test_positive_smoke_empty_refer_observables(module_headers, observable,
                                                observable_type):
    """Perform testing for enrich refer observables endpoint  to check that
     observable, on which Pulsedive doesn't have information, will return
     only search entity

    ID: CCTRI-1695-6a0c2912-0313-11eb-adc1-0242ac120002

    Steps:
        1. Send request to enrich refer observable endpoint

    Expectedresults:
        1. Check that data in response body contains only search entity from
        Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_pulsedive = get_observables(
        response_from_all_modules, MODULE_NAME)

    # check that we have only one response from Pulsedive
    assert type(response_from_pulsedive) == dict, ('Got 2 entities'
                                                   'from Pulsedive')

    assert response_from_pulsedive['module'] == MODULE_NAME
    assert response_from_pulsedive['module_instance_id']
    assert response_from_pulsedive['module_type_id']

    assert response_from_pulsedive['categories'] == [MODULE_NAME, 'Search']
