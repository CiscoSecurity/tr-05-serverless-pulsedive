import pytest

from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_indicator_base(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable from Pulsedive

    ID: CCTRI-910-22c91fdc-31e7-4951-993e-c2a90a92d434

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '2.2.2.2'}]

    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    indicators = get_observables(
        response, 'Pulsedive')['data']['indicators']
    assert indicators['count'] == 6

    for indicator in indicators['docs']:
        assert indicator['id']
        assert 'start_time' in indicator['valid_time']
        assert indicator['type'] == 'indicator'
        assert indicator['schema_version']

        assert indicator['short_description']
        assert indicator['tlp'] == 'white'

    indicator = [i for i in indicators['docs'] if
                 i.get('tags') == ['general']][0]
    assert indicator['id']
    assert indicator['tags'] == ['general']
    assert indicator['source_uri'].startswith(
        'https://pulsedive.com/threat/?tid=')
    assert indicator['producer'] == 'Pulsedive'
    assert indicator['short_description'] == 'CryptoMining'
    assert indicator['severity'] == 'Low'
    assert indicator['tlp'] == 'white'


@pytest.mark.parametrize(
    'observable,observable_type',
    (('185.141.25.242', 'ip'),
     ('yizaiwl.cc', 'domain'),
     ('https://www.google.com/', 'url'))
)
def test_positive_indicators(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable from Pulsedive

    ID: CCTRI-910-db541ad9-22a2-469b-bb23-cceaab72b56d

    Steps:
        1. Send request to enrich deliberate observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    indicators = get_observables(
        response, 'Pulsedive')['data']['indicators']
    assert indicators['count'] > 0

    for indicator in indicators['docs']:
        assert indicator['id']
        assert 'start_time' in indicator['valid_time']
        assert indicator['type'] == 'indicator'
        assert indicator['schema_version']
        assert indicator['short_description']
        assert indicator['tlp'] == 'white'
