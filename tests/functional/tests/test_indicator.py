from ctrlibrary.core.utils import get_observables
from ctrlibrary.threatresponse.enrich import enrich_observe_observables


def test_positive_indicator(module_headers):
    """Perform testing for enrich observe observables endpoint to get
    indicators for observable from Pulsedive

    ID: CCTRI-

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

        if indicator['short_description'] in ('hosted on common ISP',
                                              'found in threat feeds'):
            assert indicator['producer'] in 'Pulsedive'
            assert 'end_time' in indicator['valid_time']
        else:
            assert indicator['producer'] in ('Pulsedive', 'ZeroDot1')
            assert indicator['tags']

            if indicator['short_description'] == 'Pulsedive':
                assert indicator['source_uri'].startswith(
                    'https://pulsedive.com/threat/?tid=')

            if indicator['short_description'] == 'ZeroDot1':
                assert indicator['source_uri'].startswith(
                    'https://pulsedive.com/feed/?fid=')
