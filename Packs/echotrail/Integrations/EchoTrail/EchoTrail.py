"""
Integration Information:
Contact: 
API Documentation:
EchoTrail:
"""

from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import json
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR

''' CLIENT CLASS '''


class Client(BaseClient):
    """Client class to interact with the service API

    This Client implements API calls, and does not contain any XSOAR logic.
    Should only do requests and return data.
    It inherits from BaseClient defined in CommonServer Python.
    Most calls use _http_request() that handles proxy, SSL verification, etc.
    For this  implementation, no special attributes defined
    """

    # TODO: ADD HERE THE FUNCTIONS TO INTERACT WITH YOUR PRODUCT API
    def echotrail_searchterm(self, searchTerm):
        """
        Get a  full summary of the requested filename or hash. The summary will contain similar
            information to what can be found in a search on our website.

        Args: 
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
        Raises:
            e: _description_
        Returns:
            Description
            EchoTrail Prevalence Score
            Host Prevalence, Execution Rank
            Top 20 Parents
            Top 20 Children
            top 20 Grandparents
            Top 20 hashes/filenames
            Top 20 Paths
            Top 20 Network connection ports
            Intel
        """
        response = self._http_request("GET", "insights/{}".format(searchTerm))
        if 'message' in response:
            return response['message']
        else:
            return response
        
    def echotrail_searchterm_field(self, searchTerm, field):
        """
        Get one particular field from the summary results. If you only need access to one field in
        the above summary, use this resource as it will be much more efficient to fetch the one 
        field you need.

        Args:
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
            field (str): must be one of description, rank, host_prev, eps, parents, children, grandparents, 
                hashes, paths, network, intel

        Raises:
            e: _description_
            ValueError: _description_

        Returns:
            str: a field from the summary results
        """
        if field in {'description', 'rank', 'host_prev', 'eps', 'parents', 'children', 
                     'grandparents', 'hashes', 'paths', 'network', 'intel'}:
            response = self._http_request("GET", "insights/{}/{}".format(searchTerm, field))
            if 'message' in response:
                return response['message']
            else:
                return response[field]
        else:
            return "Invalid Field"

    def echotrail_searchterm_field_subsearch(self, searchTerm, field, subsearch):
        """For fields with a list of results, such as parents, this resource gives you the ability \
        to subsearch that list. Subsearch can be any string to search for within the results of \
        the field search. For example, when subsearching a list of parents, the subsearch string \
        should be a filename with extension.

        Args:
            searchTerm (str): Windows file name with extension (e.g. svchost.exe), SHA256 Hash or MD5 Hash
            field (str): must be one of description, rank, host_prev, eps, parents, children, grandparents,
                \ hashes, paths, network, intel
            subsearch (str): A substring to search for

        Raises:
            e: _description_
            ValueError: _description_

        Returns:
            str: Value cooresponding to the key provided as subsearch 
        """
        if field in ['parents', 'children', 'grandparents', 'hashes', 'paths']:
            response = self._http_request(self, "GET", "insights/{}/{}/{}".format(searchTerm, field, subsearch))
            if 'message' in response:
                return response['message']
            else:
                return response[subsearch]
        else:
            return "Invalid Field"
        return response


''' HELPER FUNCTIONS '''


# TODO: ADD HERE ANY HELPER FUNCTION YOU MIGHT NEED (if any)

''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: client to use

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    message: str = ''
    try:
        # TODO: ADD HERE some code to test connectivity and authentication to your service.
        # This  should validate all the inputs given in the integration configuration panel,
        # either manually or by using an API that uses them.
        response = client.echotrail_search("cmd.exe")['description']
        if 'cmd.exe is the name' in response.lower():
            demisto.results('ok')
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = 'Could not connect to server'
    finally:
        return message


def echotrail_searchterm_command(client: Client, searchTerm: str) -> CommandResults:
    result = client.echotrail_searchterm(searchTerm)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm',
        outputs_key_field='' + searchTerm,
        outputs=result,
        raw_response=json.dumps(result)
    )
    
    
def echotrail_searchterm_field_command(client: Client, searchTerm: str, field: str) -> CommandResults:
    result = client.echotrail_searchterm_field(searchTerm, field)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm',
        outputs_key_field='' + searchTerm + '.' + field,
        outputs=result
    )
    
    
def echotrail_searchterm_field_subsearch_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = args.get('searchTerm')
    field = args.get('field')
    subsearch = args.get('subsearch')
    result = client.echotrail_searchterm_field_subsearch(searchTerm, field, subsearch)
    
    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


''' MAIN FUNCTION '''


def main() -> None:
    """main function, parses params and runs command functions
    """

    # api_key = demisto.params().get('credentials', {}).get('password')
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()
    base_url = urljoin('https://api.echotrail.io/', '/v1/private')  # params.get('url'), '/v1/private/')
    verify_certificate = False  # not argToBoolean(params('insecure', False))
    #user_agent = ''
    proxy = False  # not argToBoolean(params.get('proxy', False))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:

        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        # headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'X-Api-key': params.get('apikey')},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)
        elif command == 'echotrail_searchterm':
            result = echotrail_searchterm_command(client, args)
        elif command == 'echotrail_searchterm_field':
            result = echotrail_searchterm_field_command(client, args)
        elif command == 'echotrail_searchterm_field_subsearch_command':
            result = echotrail_searchterm_field_subsearch_command(client, args)
        else:
            raise NotImplementedError(f'Command {command} is not implemented')
        return_results(result)

    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
