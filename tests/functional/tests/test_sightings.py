from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_sighting_domain(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable with domain from Pulsedive

    ID: CCTRI-909-c7d774d4-f9d1-4406-801d-1c03c186f877

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Pulsedive

    Importance: Critical
    """
    observable = {'type': 'domain', 'value': 'brehmen.com'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )
    sightings = get_observables(
        response['data'], 'Pulsedive')['data']['sightings']
    assert sightings['count'] == 5

    for sighting in sightings['docs']:
        assert sighting['count'] == 1
        assert sighting['id'].startswith('transient:sighting-')
        assert sighting['description']
        assert sighting['confidence'] == 'Medium'
        assert 'start_time' in sighting['observed_time']
        assert sighting['schema_version']
        assert sighting['type'] == 'sighting'
        assert sighting['source'] == 'Pulsedive'

        assert len(sighting['observables']) == 1
        assert sighting['observables'][0] == observable

        assert len(sighting['relations']) == 2
        for relation in sighting['relations']:
            assert relation['origin'] == 'Pulsedive Enrichment Module'
            assert relation['relation'] == 'Resolved_To'
            assert relation['source'] == {'value': 'brehmen.com',
                                          'type': 'domain'}
            assert relation['related']['value'] in ('81.169.145.159',
                                                    '2a01:238:20a:202:1159::')
            assert relation['related']['type'] in ('ip', 'ipv6')


def test_positive_sighting_ip(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable with ip from Pulsedive

    ID: CCTRI-909-cd609f51-de20-4b7d-beb8-07d947cb5e9d

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Pulsedive

    Importance: Critical
    """
    observable = {'type': 'ip', 'value': '1.1.1.1'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )
    sightings = get_observables(
        response['data'], 'Pulsedive')['data']['sightings']
    assert sightings['count'] == 10

    for sighting in sightings['docs']:
        assert sighting['count'] == 1
        assert sighting['id'].startswith('transient:sighting-')

        assert sighting['description']
        assert sighting['confidence'] == 'Medium'

        assert 'start_time' in sighting['observed_time']
        assert sighting['schema_version']

        assert sighting['type'] == 'sighting'
        assert sighting['source'] == 'Pulsedive'

        assert len(sighting['observables']) == 1
        assert sighting['observables'][0] == observable


def test_positive_sighting_url(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    sightings for observable with url from Pulsedive

    ID: CCTRI-909-23001f19-3f74-41ee-945c-20477892d921

    Steps:
        1. Send request to enrich observe observable endpoint

    Expectedresults:
        1. Check that data in response body contains expected sightings for
            observable from Pulsedive

    Importance: Critical
    """
    observable = {'type': 'url', 'value': 'https://www.google.com/'}
    response = enrich_observe_observables(
        payload=[observable],
        **{'headers': module_headers}
    )
    sightings = get_observables(
        response['data'], 'Pulsedive')['data']['sightings']
    assert sightings['count'] == 25

    for sighting in sightings['docs']:
        assert sighting['count'] == 1
        assert sighting['id'].startswith('transient:sighting-')

        assert sighting['description']
        assert sighting['confidence'] == 'Medium'

        assert 'start_time' in sighting['observed_time']
        assert sighting['schema_version']

        assert sighting['type'] == 'sighting'
        assert sighting['source'] == 'Pulsedive'

        assert len(sighting['observables']) == 1
        assert sighting['observables'][0] == observable
