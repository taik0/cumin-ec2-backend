""" AWS EC2 Backend."""

import pyparsing as pp

from boto3 import session

from cumin import nodeset_fromlist, CuminError
from cumin.backends import BaseQuery, InvalidQueryError

def grammar():
    """Define the query grammar.

    Backus-Naur form (BNF) of the grammar::

        <grammar> ::= "*" | <items>
          <items> ::= <item> | <item> <whitespace> <items>
           <item> ::= <key>:<value>
          <value> ::= <value> | [ <value> ]

    Given that the pyparsing library defines the grammar in a BNF-like style, for the details of the
    tokens not specified above check directly the source code.

    Returns:
        pyparsing.ParserElement: the grammar parser.

    """
    # Key-value tokens: key:value
    # Lowercase key, all printable characters except the parentheses that are part of the global
    # grammar for the value
    quoted_string = pp.quotedString.copy().addParseAction(pp.removeQuotes)
    key = (quoted_string | pp.Word(pp.srange('[a-z0-9-.]'), min=2))('key')
    all_but_par = ''.join([c for c in pp.printables if c not in ('(', ')', '{', '}', '[', ']')])
    value = (pp.nestedExpr(opener='[', closer=']', ignoreExpr=quoted_string) |
             (quoted_string | pp.Word(all_but_par)))('value')
    item = pp.Combine(key + ':' + value)

    # Final grammar, see the docstring for its BNF based on the tokens defined above
    # Groups are used to split the parsed results for an easy access
    return pp.Group(pp.Literal('*')('all')) | pp.OneOrMore(pp.Group(item))


class EC2Query(BaseQuery):
    """EC2Query query builder.

    Query VMs deployed in AWS EC2 using boto3.
    """

    grammar = grammar()
    """:py:class:`pyparsing.ParserElement`: load the grammar parser only once in a singleton-like way."""

    def __init__(self, config):
        """Override parent class constructor for specific setup.
        :Parameters:
            according to parent :py:meth:`cumin.backends.BaseQuery.__init__`.
        """
        super().__init__(config)
        self.ec2_config = self.config.get('ec2', {})
        self.ec2_profile = self.ec2_config.get('profile', 'default')
        self.ec2_region = self.ec2_config.get('region', None)
        self.ec2_access_key = self.ec2_config.get('access_key_id', None)
        self.ec2_secret_key = self.ec2_config.get('secret_access_key', None)
        self.address_type = self.ec2_config.get('address_type', 'PrivateDnsName')
        self.ec2_params = self._get_default_params()

    def _get_default_params(self):
        """Return the default parameters dictionary.
        Returns:
            dict: the dictionary with the default parameters.
        """
        params = {'instance-state-name': ['running']}
        cfg_params = self.ec2_config.get('params', {})
        params.update(cfg_params)
        return params

    def _execute(self):
        """Concrete implementation of parent abstract method.
        :Parameters:
            according to parent :py:meth:`cumin.backends.BaseQuery._execute`.
        Returns:
            ClusterShell.NodeSet.NodeSet: with the FQDNs of the matching hosts.
        """
        return self._get_ec2_hosts()

    def _parse_token(self, token):
        """Concrete implementation of parent abstract method.

        :Parameters:
            according to parent :py:meth:`cumin.backends.BaseQuery._parse_token`.

        Raises:
            cumin.backends.InvalidQueryError: on internal parsing error.

        """
        if not isinstance(token, pp.ParseResults):  # pragma: no cover - this should never happen
            raise InvalidQueryError('Expecting ParseResults object, got {type}: {token}'.format(
                type=type(token), token=token))

        token_dict = token.asDict()
        self.logger.trace('Token is: %s | %s', token_dict, token)

        if 'key' in token_dict and 'value' in token_dict:
            self.ec2_params[token_dict['key']] = token_dict['value']
        elif 'all' in token_dict:
            pass  # nothing to do, ec2_params have the right defaults
        else:  # pragma: no cover - this should never happen
            raise InvalidQueryError('Got unexpected token: {token}'.format(token=token))

    def _get_ec2_hosts(self):
        """Return a NodeSet with the list of matching hosts based on the parameters.
        Returns:
            ClusterShell.NodeSet.NodeSet: with the FQDNs of the matching hosts.
        """

        ec2_client = session.Session(profile_name=self.ec2_profile,
                                     region_name=self.ec2_region,
                                     aws_access_key_id=self.ec2_access_key,
                                     aws_secret_access_key=self.ec2_secret_key).client('ec2')
        ec2_paginator = ec2_client.get_paginator('describe_instances')
        ec2_filters = self._ec2_build_filters()

        # response is an iterator
        response = ec2_paginator.paginate(Filters=ec2_filters)
        hosts = []
        for item in response:
            hosts += self._parse_response(item)
        return nodeset_fromlist(hosts)

    def _parse_response(self, response):
        """Parse a describe_instances result to build the response
        :Parameters:
            A boto3 ec2 client describe_instances response
        Returns:
            A list of hostnames
        """
        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            raise CuminError('Invalid response status code: {status_code}'.format(
                status_code=response['ResponseMetadata']['HTTPStatusCode']))

        if not response['Reservations']:
            return []

        address_types = ['PrivateDnsName', 'PublicDnsName', 'PrivateIpAddress',
                         'PublicIpAddress']
        if self.address_type not in address_types:
            host_key = 'PrivatDnsName'
        else:
            host_key = self.address_type

        return [instance[host_key] for res in response['Reservations']
                for instance in res['Instances']]

    def _ec2_build_filters(self):
        """Returns a list of filters for the ec2 client.
        A filter is a dict with the 'Name' and 'Values' keys.
        A filter 'Value' can be an item or a list of items
        A filter is a dict like: {'Name': 'string', 'Values': [ 'string', ]}

        Returns:
            list: a list of filters
        """
        filters = []
        for key in self.ec2_params:
            if isinstance(self.ec2_params[key], list):
                val = self.ec2_params[key]
            else:
                val = [self.ec2_params[key]]
            filters.append({'Name': key, 'Values': val})
        return filters

GRAMMAR_PREFIX = 'E'
""":py:class:`str`: the prefix associate to this grammar, to register this backend into the general grammar.
Required by the backend auto-loader in :py:meth:`cumin.grammar.get_registered_backends`."""

query_class = EC2Query
"""Required by the backend auto-loader in :py:meth:`cumin.grammar.get_registered_backends`."""
