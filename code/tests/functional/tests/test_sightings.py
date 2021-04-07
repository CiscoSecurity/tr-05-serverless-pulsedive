import pytest
from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    SOURCE,
    PULSEDIVE_URL,
    CTR_ENTITIES_LIMIT
)


@pytest.mark.parametrize(
    'observable_type, observable',
    (
     ('url', 'http://51jianli.cn/images'),
     ('ip', '1.1.1.1'),
     ('domain', 'yk.cnxc.tk'),
     )
)
def test_positive_sighting(module_headers, observable, observable_type):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observables from Pulsedive

    ID: CCTRI-909-c7d774d4-f9d1-4406-801d-1c03c186f877

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observables from Pulsedive

    Importance: Critical
    """
    observables = [{'type': observable_type, 'value': observable}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )

    response_from_pulsedive = get_observables(response_from_all_modules,
                                              MODULE_NAME)

    assert response_from_pulsedive['module'] == MODULE_NAME
    assert response_from_pulsedive['module_instance_id']
    assert response_from_pulsedive['module_type_id']

    sightings = response_from_pulsedive['data']['sightings']
    assert len(sightings['docs']) > 0

    for sighting in sightings['docs']:
        assert sighting['count'] == 1
        assert sighting['id'].startswith('transient:sighting-')
        assert sighting['description']
        assert sighting['confidence'] == 'Medium'
        assert sighting['observed_time']['start_time'] == (
            sighting['observed_time']['end_time']
        )
        assert sighting['schema_version']
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == SOURCE
        assert sighting['source_uri'].startswith(PULSEDIVE_URL)

        assert len(sighting['observables']) == 1
        assert sighting['observables'] == observables
        if sighting['description'] == 'Active DNS':
            for relation in sighting['relations']:
                assert relation['origin'] == f'{SOURCE} Enrichment Module'
                assert relation['relation'] == 'Resolved_To'

                if observable_type == 'domain':
                    assert relation['source'] == (
                        observables[0]
                    )
                    assert relation['related']

                if observable_type == 'ip':
                    assert relation['source']['type'] == 'domain'
                    assert relation['source']['value']
                    assert relation['related'] == (
                        observables[0]
                    )

    assert sightings['count'] == len(sightings['docs']) <= CTR_ENTITIES_LIMIT
    if observable_type in ('ip', 'domain'):
        assert len(
            [sighting for sighting in sightings['docs'] if
             sighting['description'] == 'Active DNS']
        ) == 1
