from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables
from tests.functional.tests.constants import (
    MODULE_NAME,
    CTR_ENTITIES_LIMIT
)


def test_positive_relationship_detail(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    relationships for observable from Pulsedive

    ID: CCTRI-911-93c1caf8-ffc4-4edb-afbb-545cf9932270

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected relationships
           for observable from Pulsedive.
           Each sighting has one relationship with indicator

    Importance: Critical
    """
    observable = [{'type': 'ip', 'value': '1.1.1.1'}]
    response_from_all_modules = enrich_observe_observables(
        payload=observable,
        **{'headers': module_headers}
    )
    response_from_pulsedive_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive_module['module'] == MODULE_NAME
    assert response_from_pulsedive_module['module_instance_id']
    assert response_from_pulsedive_module['module_type_id']

    relationships = response_from_pulsedive_module['data']['relationships']
    sightings = response_from_pulsedive_module['data']['sightings']
    indicators = response_from_pulsedive_module['data']['indicators']
    assert len(relationships['docs']) > 0

    # sighting and indicator not less then relationships
    assert sightings['count'] and (
        indicators['count']) >= relationships['count']

    sightings_id = [s['id'] for s in sightings['docs']]
    indicators_id = [i['id'] for i in indicators['docs']]

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['tlp'] == 'white'
        assert relationship['type'] == 'relationship'
        assert relationship['relationship_type'] in (
            'sighting-of', 'member-of')
        assert relationship['target_ref'] in indicators_id
        assert relationship['source_ref'] in sightings_id
        assert relationship['id'].startswith('transient:relationship-')

        assert relationships['count'] == len(
            relationships['docs']) <= CTR_ENTITIES_LIMIT


def test_positive_relationship_several_observables(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    relationships for several observables from Pulsedive

    ID: CCTRI-911-338eaa11-9c56-4d70-b8da-0772373d8ef8

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected relationships
           for observables from Pulsedive

    Importance: Critical
    """
    observables = [{'type': 'ip', 'value': '1.1.1.1'},
                   {'type': 'ip', 'value': '2.2.2.2'}]
    response_from_all_modules = enrich_observe_observables(
        payload=observables,
        **{'headers': module_headers}
    )
    response_from_pulsedive_module = get_observables(
        response_from_all_modules, MODULE_NAME)

    assert response_from_pulsedive_module['module'] == MODULE_NAME
    assert response_from_pulsedive_module['module_instance_id']
    assert response_from_pulsedive_module['module_type_id']

    relationships = response_from_pulsedive_module['data']['relationships']
    sightings = response_from_pulsedive_module['data']['sightings']
    indicators = response_from_pulsedive_module['data']['indicators']
    assert len(relationships['docs']) > 0

    sightings_id = [s['id'] for s in sightings['docs']]
    indicators_id = [i['id'] for i in indicators['docs']]

    for relationship in relationships['docs']:
        assert relationship['schema_version']
        assert relationship['tlp'] == 'white'
        assert relationship['type'] == 'relationship'
        assert relationship['relationship_type'] in (
            'sighting-of', 'member-of')

        assert relationship['target_ref'] in indicators_id
        assert relationship['source_ref'] in sightings_id
        assert relationship['id'].startswith('transient:relationship-')

    # Each sighting exists in relationships
    sighting_indicator = {r['source_ref']: r['target_ref']
                          for r in relationships['docs']}
    if sightings['count'] <= indicators['count']:
        for sighting in sightings['docs']:
            assert sighting['id'] in sighting_indicator

    # Each indicator exists in relationships
    if indicators['count'] <= sightings['count']:
        for indicator in indicators['docs']:
            assert indicator['id'] in {
                v: k for k, v in sighting_indicator.items()
            }

    assert relationships['count'] == len(
        relationships['docs']) <= CTR_ENTITIES_LIMIT
