import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_refer_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    PULSEDIVE_URL,
    OBSERVABLE_HUMAN_READABLE_NAME
)
from urllib.parse import quote


@pytest.mark.parametrize(
    'observable,observable_type',
    (
     ('1.1.1.1', 'ip'),
     ('brehmen.com', 'domain'),
     ('2a01:238:20a:202:1159::', 'ipv6'),
     ('http://juanthradio.com/Script/DOC/', 'url'),
     )
)
def test_positive_refer_observable(module_headers, observable,
                                   observable_type):
    """Perform testing for enrich refer observables endpoint to get
    data for observable from Pulsedive

    ID: CCTRI-1007-e6401994-dbef-4467-9792-72f80fd2faa1

    Steps:
        1. Send request to enrich refer observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected refer field for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response = enrich_refer_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']

    refers = get_observables(response, MODULE_NAME)

    for refer in refers:
        assert refer['id'].startswith('ref-pulsedive') and (
            refer['id'].endswith(
                f'{observable_type}-{quote(observable, safe="")}'))
        assert refer['module'] == MODULE_NAME
        assert refer['module_instance_id']
        assert refer['module_type_id']

        if 'Search' in refer['title']:
            assert refer['title'] == (
                f'Search for this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
            assert refer['description'] == (
                f'Lookup this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]} '
                f'on {MODULE_NAME}')
            assert refer['categories'] == [MODULE_NAME, 'Search']
            assert refer['url'].startswith(f'{PULSEDIVE_URL}/browse/')
        else:
            assert refer['title'] == (
                f'Browse {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
            assert refer['description'] == (
                f'Browse this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}'
                f' on {MODULE_NAME}')
            assert refer['categories'] == [MODULE_NAME, 'Browse']
            assert refer['url'].startswith(f'{PULSEDIVE_URL}/indicator/')
