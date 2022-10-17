"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import io
import pytest
#  from CommonServerPython import *
import json
#  from echotrail_unittest_test import test_echotrail_searchterm


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'searchterm, field, expected_response',
    [
        ('svchost.exe', 'paths', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'parents', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'grandparents', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'children', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'network', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'hashes', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'rank', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'host_prev', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'eps', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'intel', util_load_json('test_data/echotrail_svchost.json')),
        ('svchost.exe', 'description', util_load_json('test_data/echotrail_svchost.json'))
    ]
)
def test_echotrail_searchterm_field(searchterm, field, expected_response, mocker):
    """Unit Test
    Given
    Args:
        searchterm (str): A field keyword to search with
    When:
        field is one of 'description', 'rank', 'host_prev', 'eps', 'parents', 'children', 'grandparents', 
        'hashes', 'paths', 'network', 'intel'
    Then:
        validate that when the '/insights/{searchterm}/{field}' command is called and field is
        valid correct results are returned
    """
    from EchoTrail import echotrail_searchterm_field_command
    from EchoTrail import Client
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(Client, '_http_request', return_value=expected_response)
    expected_result = expected_response[field]
    response = echotrail_searchterm_field_command(client, searchterm, field)
    assert response.outputs == expected_result


def test_echotrail_searchterm_field_invalid_field(mocker):
    """Unit Test 
    Given:
    - A field keyword to search with
        Args:
            mocker (str): searchTerm
    When:
    - Field keyword is invalid, not one of 'description', 'rank' 'host_prev', 'eps', 
      'parents', 'childern', 'grandparents', 'hashes', 'paths', 'network', 'intel'
    Then:
    - Validate the returned result is "Invalid Field"
    """
    from EchoTrail import echotrail_searchterm_field_command
    from EchoTrail import Client
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/echotrail_searchterm_invalid.json'))
    expected_result = util_load_json('test_data/echotrail_searchterm_invalid.json')['message']
    response = echotrail_searchterm_field_command(client, 'svchost.exe', 'asdfjkl')
    assert response.outputs == expected_result
    
    
def test_echotrail_searchterm_field_subsearch_invalid_field(mocker):
    """Unit Test
    Given:
    - a field keyword to search with
    When:
    - field keyword is invalid, not one of 'parents', 'children', 'grandparents', 'hashes', 'paths'
    Then:
    - validate that returned result is "Invalid Field"
    """
    from EchoTrail import echotrail_searchterm_field_command
    from EchoTrail import Client
    # client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/echotrail_searchterm_invalid.json'))
    return_value = util_load_json('test_data/echotrail_searchterm_invalid.json')['message']
    response = echotrail_searchterm_field_command(client, 'svchost.exe', 'asdfjkl')
    assert response.outputs == return_value
    
def test_echotrail_searchterm_field_subsearch(mocker):
    """Unit Test
    Given:
    - a searchTerm to search with
    - a field keyword to search with
    - a subsearch keyword to look for
    When:
    - searchTerm normally returns results
    - field keyword is valid, one of 'parents', 'children', 'grandparents', 'hashes', 'paths'
    - and subsearch keyword exists in results
    Then:
    - Validate the returned result
    """
    from EchoTrail import echotrail_searchterm_field_subsearch_command
    from EchoTrail import Client
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/echotrail_searchterm_msmpeng.json'))
    expected_result = util_load_json('test_data/echotrail_searchterm_msmpeng.json')['message']
    response = echotrail_searchterm_field_subsearch_command(client, 'svchost.exe', 'myparents', 'msmpeng.exe')
    assert response.outputs == expected_result
    
#  TODO: Tests for when subsearch term is not found