import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    SOURCE,
    CTR_ENTITIES_LIMIT, PULSEDIVE_URL
)


def test_positive_indicator_details(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicator for observable from Pulsedive

    ID: CCTRI-910-22c91fdc-31e7-4951-993e-c2a90a92d434

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '2.2.2.2'}]

    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_pulsedive_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive_module['module'] == MODULE_NAME
    assert response_from_pulsedive_module['module_instance_id']
    assert response_from_pulsedive_module['module_type_id']

    indicators = response_from_pulsedive_module['data']['indicators']
    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert indicator['id'].startswith('transient:indicator-')
        assert indicator['valid_time']['start_time']
        assert indicator['type'] == 'indicator'
        assert indicator['schema_version']
        assert indicator['short_description']
        assert indicator['tlp'] == 'white'
        assert indicator['source'] == SOURCE

    indicator = [i for i in indicators['docs'] if i.get('source_uri')
                 == 'https://pulsedive.com/feed/?fid=60'][0]
    assert indicator['id'].startswith('transient:indicator-')
    assert indicator['tags'] == ['abuse']
    assert indicator['source_uri'].startswith(
        'https://pulsedive.com/feed/?fid=')
    assert indicator['producer'] == 'ZeroDot1'
    assert indicator['short_description'] == 'Feed: ZeroDot1\'s Bad IPs '
    assert indicator['tlp'] == 'white'

    assert indicators['count'] == len(indicators['docs']) <= CTR_ENTITIES_LIMIT


@pytest.mark.parametrize(
    'observable,observable_type',
    (('185.141.25.242', 'ip'),
     ('yizaiwl.cc', 'domain'),
     ('https://www.google.com/', 'url'))
)
def test_positive_indicators_by_type(
        module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable different types from Pulsedive

    ID: CCTRI-910-db541ad9-22a2-469b-bb23-cceaab72b56d

    Steps:
        1. Send request to enrich observe observables endpoint

    Expectedresults:
        1. Check that data in response body contains expected indicators for
            observable from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]

    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )['data']
    response_from_pulsedive_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive_module['module'] == MODULE_NAME
    assert response_from_pulsedive_module['module_instance_id']
    assert response_from_pulsedive_module['module_type_id']

    indicators = response_from_pulsedive_module['data']['indicators']
    assert len(indicators['docs']) > 0

    for indicator in indicators['docs']:
        assert indicator['id'].startswith('transient:indicator-')
        assert indicator['valid_time']['start_time']
        assert indicator['producer']
        assert indicator['type'] == 'indicator'
        assert indicator['schema_version']
        assert indicator['short_description']
        assert indicator['tlp'] == 'white'
        assert indicator['source'] == SOURCE
        if 'source_uri' in indicator:
            assert indicator['source_uri'].startswith(PULSEDIVE_URL)

    assert indicators['count'] == len(indicators['docs']) <= CTR_ENTITIES_LIMIT
