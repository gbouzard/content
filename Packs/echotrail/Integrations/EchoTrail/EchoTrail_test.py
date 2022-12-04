"""Base Integration for Cortex XSOAR - Unit Tests file

Pytest Unit Tests: all funcion names must start with "test_"

More details: https://xsoar.pan.dev/docs/integrations/unit-testing

MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"

You must add at least a Unit Test function for every XSOAR command
you are implementing with your integration
"""

import ast
import io
import pytest
from CommonServerPython import set_integration_context, get_integration_context
import EchoTrail
import json
from datetime import timedelta, datetime
#  import demistomock as demisto  # type: ignore


def util_load_json(path):
    with io.open(path, mode='r', encoding='utf-8') as f:
        return json.loads(f.read())


@pytest.mark.parametrize(
    'searchterm, field, expected_response',
    [
        ('svchost.exe', 'paths', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'parents', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'grandparents', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'children', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'network', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'hashes', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'rank', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'host_prev', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'eps', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'intel', util_load_json('./test_data/echotrail_svchost.json')),
        ('svchost.exe', 'description', util_load_json('./test_data/echotrail_svchost.json'))
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
    mocker.patch.object(client, '_http_request', return_value=expected_response)
    expected_result = expected_response[field]
    args = {'searchTerm': searchterm, 'field': field}
    response = echotrail_searchterm_field_command(client, args)
    assert response.outputs[field] == expected_result


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
    mocker.patch.object(client, '_http_request', return_value=util_load_json('test_data/echotrail_searchterm_invalid.json'))
    expected_result = util_load_json('test_data/echotrail_searchterm_invalid.json')['message']
    args = {'searchTerm': 'svchost.exe', 'field': 'asdfjkl'}
    response = echotrail_searchterm_field_command(client, args)
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
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(Client, '_http_request', return_value=util_load_json('test_data/echotrail_searchterm_invalid.json'))
    return_value = util_load_json('test_data/echotrail_searchterm_invalid.json')['message']
    args = {'searchTerm': 'svchost.exe', 'field': 'asdfjkl'}
    response = echotrail_searchterm_field_command(client, args)
    assert response.outputs == return_value


def test_echotrail_searchterm_field_subsearch(mocker):
    """Unit Test
    Given:
        a searchTerm to search with
        a field keyword to search with
        a subsearch keyword to look for
    When:
        searchTerm normally returns results
        field keyword is valid, one of 'parents', 'children', 'grandparents', 'hashes', 'paths'
        and subsearch keyword exists in results
    Then:
        Validate the returned result
    """
    from EchoTrail import echotrail_searchterm_field_subsearch_command
    from EchoTrail import Client
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(client, '_http_request', return_value=util_load_json(
        'test_data/echotrail_searchterm_svchost_parents_services.json'))
    expected_result = util_load_json('test_data/echotrail_searchterm_svchost_parents_services.json')
    args = {'searchTerm': 'svchost.exe', 'field': 'parents', 'subsearch': 'services.exe'}
    response = echotrail_searchterm_field_subsearch_command(client, args)
    assert response.outputs == expected_result


def test_echotrail_score(mocker):
    """Unit Test
    Given:
        All fields optional and mandatory
    When:
        Fields are properly formatted
    Then:
        Validate the returned result
    """
    from EchoTrail import echotrail_score_command
    from EchoTrail import Client
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(client, '_http_request', return_value=util_load_json('test_data/echotrail_score_cmd.json'))
    expected_result = util_load_json('test_data/echotrail_score_cmd.json')
    args = EchoTrail.ExecutionProfile(hostname='hostname', image='C:\\Windows\\System32\\cmd.exe',
                                      parent_image='C:\\Windows\\explorer.exe',
                                      grandparent_image='C:\\Windows\\System32\\services.exe',
                                      ehash='ec436aeee41857eee5875efdb7166fe043349db5f58f3ee9fc4ff7f50005767f',
                                      parent_hash='ec436aeee41857eee5875efdb7166fe043349db5f58f3ee9fc4ff7f50005767f',
                                      commandline='-q foo',
                                      children=['find.exe', 'calc.exe'],
                                      network_ports=[443, 80],
                                      environment='environment_a',
                                      record_execution=False
                                      )
    response = echotrail_score_command(client, args)
    assert response.outputs == expected_result


def test_echotrail_score_some_fields(mocker):
    """Unit Test
    Given:
        All fields mandatory, some of the optional fields
    When:
        Provided fields are properly formatted
    Then:
        Validate the returned result
    """
    from EchoTrail import Client
    import EchoTrail
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(client, '_http_request', return_value=util_load_json('test_data/echotrail_score_some_fields.json'))
    expected_result = util_load_json('test_data/echotrail_score_some_fields.json')
    args = EchoTrail.ExecutionProfile(hostname='hostname',
                                      image='C:\\Windows\\System32\\cmd.exe',
                                      parent_image='C:\\Windows\\explorer.exe',
                                      grandparent_image='',
                                      ehash='ec436aeee41857eee5875efdb7166fe043349db5f58f3ee9fc4ff7f50005767f',
                                      parent_hash='',
                                      commandline='-q foo',
                                      children=["find.exe", "calc.exe"],
                                      network_ports=None,
                                      environment='environment_a',
                                      record_execution=False
                                      )
    response = EchoTrail.echotrail_score_command(client, args)
    assert response.outputs == expected_result


@pytest.mark.parametrize(
    'calling_method, mocked_response, mocked_integration_cache', [
        ('echotrail_searchterm',
            util_load_json('test_data/echotrail_svchost.json'),
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_queries.json'))
    ]
)
def test__is_expired_cache_entry_searchterm_unexpired(calling_method, mocked_response, mocked_integration_cache, mocker):
    """Unit Test
    Given:
        a calling_method of echotrail_searchterm
        a date: e.g. 2022-11-27 15:14:29.908002
    When:
        Integration context contains a matching entry/search parameter that has been queried within 74 hours of the provided date
    Then:
        Returned value from __is_expired_cache_entry() should be False: bool
    """
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = EchoTrail.Client(base_url='', headers={'X-Api-key': '<key>'})
    for term in integration_context['searchTerms']:
        integration_context['searchTerms'][term].update({
            'timestamp': (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    for term in integration_context['searchTerms']:
        result = client.__is_expired_cache_entry__(search_term=term, cache_hours=10, calling_method='echotrail_searchterm')
        assert result is False


@pytest.mark.parametrize(
    'calling_method, mocked_response, mocked_integration_cache, search_term', [
        (
            'echotrail_searchterm_field',
            util_load_json('test_data/echotrail_smss.json'),
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'smss.exe'
        )
    ]
)
def test__is_expired_cache_entry_searchterm_field_unexpired(calling_method, mocked_response, mocked_integration_cache,
                                                            search_term, mocker):
    """Unit Test
    Given:
        a searchterm
    When:
        Searchterm has been lookup up within 74 hours
    Then:
        Returned value from __is_expired_cache_entry() should be False: bool
    """
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = EchoTrail.Client(base_url='', headers={'X-Api-key': '<key>'})
    search_term_results = integration_context['fields'][search_term]
    for r in search_term_results:
        integration_context['fields'][search_term][r].update({
            'timestamp': (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    for term in integration_context['fields']:
        result = client.__is_expired_cache_entry__(search_term=term, field='hashes',
                                                   cache_hours=10,
                                                   calling_method='echotrail_searchterm_field')
        assert result is False


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term, field, subsearch', [
        (
            'echotrail_searchterm_field_subsearch',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'smss.exe',
            'hashes',
            '4ce6cb811547ed1d0b29d86fa9ece63e5fb5dcfe680ebe1abc269a2b80b09993'
        )
    ]
)
def test__is_expired_cache_entry_searchterm_field_subsearch_unexpired(calling_method, mocked_integration_cache,
                                                                      search_term, field, subsearch, mocker):
    """Unit Test
    Given:
        a searchterm, field and subsearch term
    When:
        Searchterm has been lookup up within 74 hours
    Then:
        Returned value from __is_expired_cache_entry() should be False: bool
    """
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = EchoTrail.Client(base_url='', headers={'X-Api-key': '<key>'})
    search_term_results = integration_context['subsearches'][search_term][field]
    for str in search_term_results:
        integration_context['subsearches'][search_term][field][str].update({
            'timestamp': (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    for subsearch in integration_context['subsearches'][search_term][field]:
        result = client.__is_expired_cache_entry__(search_term=search_term,
                                                   field=field,
                                                   subsearch=subsearch,
                                                   cache_hours=10,
                                                   calling_method=calling_method)
        assert result is False


@pytest.mark.parametrize(
    'expected_response, mocked_integration_cache_before, mocked_integration_cache_after, search_term', [
        (
            util_load_json('test_data/echotrail_integration_context_no_searchterm_key_in_cache_query_response.json'),
            util_load_json('test_data/echotrail_integration_context_no_searchterm_key_in_cache_before.json'),
            util_load_json('test_data/echotrail_integration_context_no_searchterm_key_in_cache_after.json'),
            'wininit.exe',
        )
    ]
)
def test_echotrail_searchterm_no_existing_searchterm_cache(expected_response, mocked_integration_cache_before,
                                                           mocked_integration_cache_after, search_term, mocker):
    """
    Unit Test
    Given:
        a searchterm
    When:
        Query results for searchterm are not cached, and there has never been a searchterm cached before
    Then:
        Before calling echotrail_searchterm_command, verify that 'searchTerms' is not a context key
        After calling echotrail_searchterm_command, Verify searchTerms is now a key in context and
            the search_term is in the context cache at ['searchTerms']['<search_term>']
    """
    from EchoTrail import Client
    from EchoTrail import echotrail_searchterm_command
    set_integration_context(mocked_integration_cache_before)
    integration_context: ast.Dict = get_integration_context()
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    mocker.patch.object(client, '_http_request', return_value=expected_response)
    args = {"searchTerm": search_term}
    assert 'searchTerms' not in integration_context
    echotrail_searchterm_command(client, args)
    set_integration_context(mocked_integration_cache_after)
    integration_context: ast.Dict = get_integration_context()
    assert 'searchTerms' in integration_context
    assert search_term in integration_context['searchTerms']


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term', [
        (
            'echotrail_searchterm',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'lsass.exe',
        )
    ]
)
def test_echotrail_searchterm_expired_cache_entry(calling_method, mocked_integration_cache, search_term, mocker):
    """
    Unit Test
    Given:
        a searchterm
    When:
        Query results for searchterm are cached and expired
    Then:
        Verify __is_expired_cache_entry__ returns True
        Verify cache now doesn't contain a given searchterm
        Verify cache still contains two other searchterms
    """
    from EchoTrail import Client
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    search_term_cache = integration_context['searchTerms']
    for st in search_term_cache:
        integration_context['searchTerms'][st].update({
            'timestamp': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    mocker.patch.object(client, '_http_request', return_value=mocked_integration_cache)
    results = client.__is_expired_cache_entry__(search_term=search_term,
                                                cache_hours=10,
                                                calling_method=calling_method)
    assert results is True
    assert search_term not in search_term_cache
    assert 'svchost.exe' in search_term_cache
    assert 'taskhostw.exe' in search_term_cache


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term, field, subsearch', [
        (
            'echotrail_searchterm_field_subsearch',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_subsearch_queries.json'),
            'wininit.exe',
            'parents',
            'fontdrvhost.exe'
        ),
        (
            'echotrail_searchterm_field_subsearch',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_subsearch_queries.json'),
            'wininit.exe',
            'hashes',
            '6f3304f91e1597435d5a74edc928bbee5ebfc88cd5a650a6dac50f919137a11c'
        )
    ]
)
def test_echotrail_searchterm_field_subsearch_expired_cache_entry(calling_method, mocked_integration_cache,
                                                                  search_term, field, subsearch, mocker):
    """
    Unit Test
    Given:
        a searchterm, field and subsearch
    When:
        Query results for echotrail-searchterm-field-subsearch are cached and expired
    Then:
        Verify __is_expired_cache_entry__ returns True
        Verify cache now doesn't contain a given searchterm-field-subsearch entry
    """

    from EchoTrail import Client
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    integration_context['subsearches'][search_term][field][subsearch].update({
        'timestamp': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
    })
    set_integration_context(integration_context)
    mocker.patch.object(client, '_http_request', return_value=mocked_integration_cache)
    results = client.__is_expired_cache_entry__(search_term=search_term,
                                                field=field,
                                                subsearch=subsearch,
                                                cache_hours=10,
                                                calling_method=calling_method)
    integration_context_again: ast.Dict = get_integration_context()
    assert results is True
    with pytest.raises(Exception):
        assert subsearch in integration_context_again['subsearches'][search_term][field]


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term, field', [
        (
            'echotrail_searchterm_field',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'smss.exe',
            'hashes'
        ),
        (
            'echotrail_searchterm_field',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries_one_entry_left.json'),
            'smss.exe',
            'grandparents'
        )
    ]
)
def test_echotrail_searchterm_field_expired_cache_entry(calling_method, mocked_integration_cache, search_term, field, mocker):
    """
    Unit Test
    Given:
        a searchterm and a field
    When:
        Query results for 'field' query are cached and expired
    Then:
        Verify __is_expired_cache_entry__ returns True
        Verify cache now doesn't contain a given field
    """
    from EchoTrail import Client
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = Client(base_url='', headers={'X-Api-key': '<key>'})
    fields_cache = integration_context['fields']
    for st in fields_cache:
        integration_context['fields'][st][field].update({
            'timestamp': (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    mocker.patch.object(client, '_http_request', return_value=mocked_integration_cache)
    results = client.__is_expired_cache_entry__(search_term=search_term,
                                                field=field,
                                                cache_hours=10,
                                                calling_method=calling_method)
    assert results is True
    if search_term in fields_cache:
        assert field not in fields_cache[search_term]


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term, expected_value', [
        (
            'echotrail_searchterm',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'lsass.exe',
            'nxserver.bin'
        )
    ]
)
def test_echotrail_searchterm_unexpired_no_api_call(calling_method, mocked_integration_cache,
                                                    search_term, expected_value, mocker):
    """
    Unit Test
    Given:
        a searchterm
    When:
        Query results are cached
    Then:
        Verify no API call to Echotrail.io is performed but results are returned
    """
    from EchoTrail import echotrail_searchterm_command
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = EchoTrail.Client(base_url='', headers={'X-Api-key': '<key>'})
    searchTerms_cache = integration_context['searchTerms'][search_term]
    for t in searchTerms_cache:
        integration_context['searchTerms'][search_term].update({
            'timestamp': (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    mocker.patch.object(client, '_http_request', return_value=mocked_integration_cache)
    args = {"searchTerm": search_term}
    results = echotrail_searchterm_command(client, args)
    assert expected_value in results.outputs['searchTerms'][search_term]['results']


@pytest.mark.parametrize(
    'calling_method, mocked_integration_cache, search_term, field, subsearch, expected_value', [
        (
            'echotrail_searchterm_field_subsearch',
            util_load_json('test_data/echotrail_integration_context_unexpired_searchterm_field_queries.json'),
            'smss.exe',
            'hashes',
            '7cfc64ff84039e354279defc4eb81d1afd4bfcc8f336b4ec699374e0dd8aa5d8',
            "['7cfc64ff84039e354279defc4eb81d1afd4bfcc8f336b4ec699374e0dd8aa5d8', '8.498267']",
        )
    ]
)
def test_echotrail_searchterm_field_subsearch_unexpired(calling_method, mocked_integration_cache,
                                                        search_term, field, subsearch, expected_value, mocker):
    """
    Unit Test
    Given:
        a searchterm, field, and subsearch term
    When:
        Query results are cached
    Then:
        Verify no API call to Echotrail.io is performed but results are returned
    """
    from EchoTrail import echotrail_searchterm_field_subsearch_command
    set_integration_context(mocked_integration_cache)
    integration_context: ast.Dict = get_integration_context()
    client = EchoTrail.Client(base_url='', headers={'X-Api-key': '<key>'})
    subsearch_cache = integration_context['subsearches'][search_term][field]
    for ss in subsearch_cache:
        integration_context['subsearches'][search_term][field][ss].update({
            'timestamp': (datetime.now() - timedelta(minutes=30)).strftime('%Y-%m-%dT%H:%M:%SZ')
        })
    mocker.patch.object(client, '_http_request', return_value=mocked_integration_cache)
    args = {"searchTerm": search_term, "field": field, "subsearch": subsearch}
    results = echotrail_searchterm_field_subsearch_command(client, args)
    assert expected_value == results.outputs['subsearches'][search_term][field][subsearch]['results']


# def test_echotrail_score_cached_entry_unexpired(mocker):
"""Unit Test
Given:
    An ExecutionProfile
When:
    ExecutionProfile has already been scored and cache has at least two entries that are not expired
Then:
    Validate that the returned result is from the cach
"""


# def test_echotrail_score_uncached(mocker):
"""Unit Test
Given:
    Two ExecutionProfiles
When:
    ExecutionProfiles are not cached and cache has at least two entries
Then:
    Entries should be cached and cache should contain the two ExecutionProfiles entries"""
