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

    references = get_observables(response, MODULE_NAME)

    for reference in references:
        assert reference['id'].startswith('ref-pulsedive') and (
            reference['id'].endswith(
                f'{observable_type}-{quote(observable, safe="")}'))
        assert reference['module'] == MODULE_NAME
        assert reference['module_instance_id']
        assert reference['module_type_id']

        if reference['title'].startswith('Search'):
            assert reference['title'] == (
                'Search for this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
            assert reference['description'] == (
                'Lookup this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]} '
                f'on {MODULE_NAME}')
            assert reference['categories'] == [MODULE_NAME, 'Search']
            assert reference['url'].startswith(f'{PULSEDIVE_URL}/browse/')
        elif reference['title'].startswith('Browse'):
            assert reference['title'] == (
                f'Browse {OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}')
            assert reference['description'] == (
                'Browse this '
                f'{OBSERVABLE_HUMAN_READABLE_NAME[observable_type]}'
                f' on {MODULE_NAME}')
            assert reference['categories'] == [MODULE_NAME, 'Browse']
            assert reference['url'].startswith(f'{PULSEDIVE_URL}/indicator/')
        else:
            raise AssertionError(f'Unknown reference: {reference["title"]!r}.')
