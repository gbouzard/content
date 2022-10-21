"""
Integration Information:
Contact:
API Documentation:
EchoTrail:
"""

import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import json
import urllib3
from typing import Dict, Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR


class ExecutionProfile:
    def __init__(self, image: str, **kwargs: Any) -> None:
        self.image = image
        self.children = kwargs['children']
        self.network_ports = kwargs['network_ports']
        self.hostname = kwargs['hostname']
        self.parent_image = kwargs['parent_image']
        self.grandparent_image = kwargs['grandparent_image']
        self.hash = kwargs['hash']
        self.parent_hash = kwargs['parent_hash']
        self.commandline = kwargs['commandline']
        self.environment = kwargs['environment']
        self.record_execution = kwargs['record_execution']


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
                return response
        else:
            return "Invalid Field"
        return response

    def echotrail_score(self, image='', hostname='', parent_image='', grandparent_image='', hash='', parent_hash='',
                        commandline='', children=None, network_ports=None, environment='', record_execution=''):
        """Scores will be broken down into 4 categories, host, environment, customer and global, when
        enough information is provided to calculate a score for each category. If an environment name
        is not provided, the default environment will be used, and an environment score will not be
        provided. Also, when individual fields, like grandparent, for example, are not provided, those
        fields will be excluded from the scoring process and the scores will be dynamically adjusted to
        account for only the fields provided.

        Args:
            image (str): If a hostname is provided, host-level scores will also be calculated
            hostname (str): Image is the only required field. Ideally it should contain a full path and executable name.
            parent_image (str): The parent path and executable name obvserved.
            grandparent_image (str): The grandparent path and executable name observed.
            hash (str): The SHA256 hash observed.
            parent_hash (str): The SHA256 hash of the parent.
            commandline (str): The commandline observed. Commandline scoring will be coming soon.
            children (arr): Any children observed.
            network_ports (arr): Any network connection ports observed.
            environment (str): This field allows for segregation of statistics for different environments. It can be used for
                different network segments or customers. It is up to the user to determine if and how this field is used.
            record_execution (bool): This field defaults to false as we don’t want to record a query as an actual real-world
                execution unless you specify that we should do so. Set this field to true for us to record the execution
                statistics.
        """
        if children is None:
            children = []
        if network_ports is None:
            network_ports = []

        payload = {
            "image": image,
            "hostname": hostname,
            "parent_image": parent_image,
            "grandparent_image": grandparent_image,
            "hash": hash,
            "parent_hash": parent_hash,
            "commandline": commandline,
            "children": children,
            "network_ports": network_ports,
            "environment": environment,
            "record_execution": False
        }
        response = self._http_request(self, "POST", "score", json_data=json.dumps(payload))
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
        response = client.echotrail_searchterm("cmd.exe")['description']
        message = str(response)
        if 'The Windows Command Prompt' in response:
            message = 'ok'
    except DemistoException as e:
        if 'Forbidden' in str(e) or 'Authorization' in str(e):  # TODO: make sure you capture authentication errors
            message = 'Authorization Error: make sure API Key is correctly set'
        else:
            message = 'Could not connect to server'
    return message


def echotrail_searchterm_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = str(args['searchTerm'])
    result = client.echotrail_searchterm(searchTerm)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm',
        outputs_key_field=searchTerm,
        outputs=result,
        raw_response=json.dumps(result),
        ignore_auto_extract=True
    )


def echotrail_searchterm_field_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = str(args['searchTerm'])
    field = str(args['field'])
    result = client.echotrail_searchterm_field(searchTerm, field)
    return CommandResults(
        outputs_prefix='EchoTrail.SearchTerm',
        outputs_key_field='' + searchTerm + '.' + field,
        outputs=result
    )


def echotrail_searchterm_field_subsearch_command(client: Client, args: Dict[str, Any]) -> CommandResults:
    searchTerm = str(args['searchTerm'])
    field = str(args['field'])
    subsearch = str(args['subsearch'])

    if (type(searchTerm) != str or type(field) != str or type(subsearch) != str):
        return_error(
            f"Failed to execute {'echotrail_searchterm_field_subsearch_command'} command. \
                Error: ['searchTerm', 'field', 'subsearch'] must be of type (str)")
    else:
        result = client.echotrail_searchterm_field_subsearch(searchTerm, field, subsearch)

    return CommandResults(
        outputs_prefix='BaseIntegration',
        outputs_key_field='',
        outputs=result,
    )


def echotrail_score_command(client: Client, execution_profile: ExecutionProfile) -> CommandResults:
    hostname = execution_profile.hostname
    image = execution_profile.image
    parent_image = execution_profile.parent_image
    grandparent_image = execution_profile.grandparent_image
    hash = execution_profile.hash
    parent_hash = execution_profile.parent_hash
    commandline = execution_profile.commandline
    children = execution_profile.children
    network_ports = execution_profile.network_ports
    environment = execution_profile.environment
    record_execution = execution_profile.record_execution

    try:
        result = client.echotrail_score(image, hostname, parent_image, grandparent_image, hash, parent_hash, commandline,
                                        children, network_ports, environment, record_execution)
        return CommandResults(
            outputs_prefix='BaseIntegration',
            outputs_key_field='',
            outputs=result,
        )
    except Exception as e:
        demisto.error("Failed to execute 'echotrail_score_command' command. Error: {}", {str(e)})
        return CommandResults(
            outputs_prefix=None,
            outputs=result,
        )


def main() -> None:
    """
    main function, parses params and runs command functions
    """
    api_key = demisto.getParam('api_key').get('password')
    args = demisto.args()
    command = demisto.command()
    base_url = urljoin('https://api.echotrail.io/', '/v1/private')
    verify_certificate = not argToBoolean(demisto.getParam('insecure'))
    proxy = not argToBoolean(demisto.getParam('proxy'))

    demisto.debug(f'Command being called is {demisto.command()}')
    try:
        # TODO: Make sure you add the proper headers for authentication
        # (i.e. "Authorization": {api key})
        # headers: Dict = {}

        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers={'X-Api-key': api_key},
            proxy=proxy)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)  # type: Optional[Any]
            demisto.results(result)
        elif command == 'echotrail_searchterm':
            result = echotrail_searchterm_command(client, args)
        elif command == 'echotrail_searchterm_field':
            result = echotrail_searchterm_field_command(client, args)
            demisto.results(result.raw_response)
        elif command == 'echotrail_searchterm_field_subsearch_command':
            result = echotrail_searchterm_field_subsearch_command(client, args)
            demisto.results(result.raw_response)
        elif command == 'echotrail_score_command':
            #  executionProfile = ExecutionProfile(args.get('image'), args.get('hostname'))# type: ExecutionProfile
            result = echotrail_score_command(client, args)
            demisto.results(result.raw_response)
            raise NotImplementedError(f'Command {command} is not implemented')
        return_results(result)
    # Log exceptions and return errors
    except Exception as e:
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
