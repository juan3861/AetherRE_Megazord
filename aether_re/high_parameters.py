"""Identity-bound observations of decompiler HighSymbol parameter instances.

These observations describe Ghidra's model after decompilation. They do not
recover original source arity, calling conventions, or call semantics.
"""
from __future__ import annotations

import hashlib
import json
import re


def _address(value):
    if type(value) is not str:
        return None
    match = re.fullmatch(r'([A-Za-z0-9_.-]{1,64}):([0-9a-fA-F]{1,16})', value)
    return match[1] + ':' + format(int(match[2], 16), 'x') if match else None


def _budget_bytes(value):
    """Compact UTF-8 JSON matching Gson with HTML escaping disabled.

    Gson still escapes the two Unicode line separators in that mode.
    Only byte length is contractual here; object member ordering is not.
    """
    compact = json.dumps(value, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    return compact.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029').encode('utf-8')


def validate_high_parameters(value, *, data, expected_target, expected_address):
    """Validate the envelope against an already validated function IR inventory."""
    def require(condition):
        if not condition:
            raise ValueError('high_parameter_observation_invalid')

    def integer(number, low, high):
        return type(number) is int and low <= number <= high

    def text(string, limit=4096):
        return type(string) is str and 1 <= len(string) <= limit

    fields = {'schema', 'stage', 'target_sha256', 'function_address', 'parameters',
              'abi_recovered', 'source_parameter_count_proved', 'call_semantics_proved'}
    require(type(value) is dict and set(value) == fields)
    require(value['schema'] == 'observed-high-parameters.v1')
    require(value['stage'] == 'high_function_after_decompilation')
    require(type(expected_target) is str and re.fullmatch('[0-9a-f]{64}', expected_target) is not None)
    require(value['target_sha256'] == expected_target)
    require(_address(expected_address) is not None
            and _address(value['function_address']) == _address(expected_address))
    require(all(value[key] is False for key in
                ('abi_recovered', 'source_parameter_count_proved', 'call_semantics_proved')))
    require(type(data) is dict and data.get('target_sha256') == expected_target
            and _address(data.get('function_address')) == _address(expected_address))
    inventory = data.get('varnodes')
    require(type(inventory) is list and len(inventory) <= 32768)
    require(all(type(node) is dict and text(node.get('id'), 256) for node in inventory))
    identities = {node['id'] for node in inventory}
    require(len(identities) == len(inventory))
    parameters = value['parameters']
    require(type(parameters) is list and len(parameters) <= 128)
    parameter_fields = {'ordinal', 'category_index', 'name', 'type_name', 'size',
                        'is_parameter', 'hidden_return', 'this_pointer', 'type_locked',
                        'name_locked', 'instances'}
    total_instances = 0
    for ordinal, parameter in enumerate(parameters):
        require(type(parameter) is dict and set(parameter) == parameter_fields)
        require(integer(parameter['ordinal'], 0, 127) and parameter['ordinal'] == ordinal)
        require(integer(parameter['category_index'], -1, 2147483647))
        require(text(parameter['name']) and text(parameter['type_name']))
        require(integer(parameter['size'], 1, 1048576) and parameter['is_parameter'] is True)
        require(all(type(parameter[key]) is bool for key in
                    ('hidden_return', 'this_pointer', 'type_locked', 'name_locked')))
        instances = parameter['instances']
        require(type(instances) is dict and set(instances) == {'available', 'total', 'omitted', 'observed'})
        require(type(instances['available']) is bool)
        require(integer(instances['total'], 0, 32768) and integer(instances['omitted'], 0, 32768))
        observed = instances['observed']
        require(type(observed) is list and len(observed) <= 32768)
        require(all(type(identity) is str and identity in identities for identity in observed))
        require(len(set(observed)) == len(observed))
        require(instances['total'] == len(observed) + instances['omitted'])
        require(instances['available'] or instances['total'] == 0)
        total_instances += instances['total']
        require(total_instances <= 32768)
    require(len(_budget_bytes(value)) <= 256 * 1024)
    return value


def bind_high_parameters(data, observation, *, expected_target, expected_address, evidence_sha256):
    """Associate existing input IDs with HighSymbols, leaving all gaps visible."""
    from aether_re.ghidra_pcode_ir import analyze_high_pcode

    checked = analyze_high_pcode(data, expected_target=expected_target,
                                expected_address=expected_address, evidence_sha256=evidence_sha256)
    validate_high_parameters(observation, data=data, expected_target=expected_target,
                             expected_address=expected_address)
    inputs = [node for node in data['varnodes'] if node['input']]
    input_ids = {node['id'] for node in inputs}
    parameters, owners = [], {}
    for parameter in observation['parameters']:
        associated = [identity for identity in parameter['instances']['observed'] if identity in input_ids]
        for identity in associated:
            owners.setdefault(identity, set()).add(parameter['ordinal'])
        parameters.append(dict(ordinal=parameter['ordinal'], name=parameter['name'],
                               input_varnodes=associated,
                               instance_enumeration_available=parameter['instances']['available'],
                               omitted_instances=parameter['instances']['omitted'],
                               status='observed_input_association' if associated else 'no_observed_input'))
    used = set()
    for parameter in parameters:
        if any(len(owners[identity]) > 1 for identity in parameter['input_varnodes']):
            parameter['status'] = 'ambiguous_input_association'
        if parameter['status'] == 'observed_input_association':
            used.update(parameter['input_varnodes'])
    unbound = [node['id'] for node in inputs if node['id'] not in used]
    omitted = sum(parameter['omitted_instances'] for parameter in parameters)
    complete = (checked['summary']['status'] == 'structurally_valid'
                and not checked['summary']['unresolved_liveins'] and not unbound and not omitted
                and all(parameter['instance_enumeration_available'] for parameter in parameters)
                and all(parameter['status'] == 'observed_input_association' for parameter in parameters))
    observation_digest = hashlib.sha256(json.dumps(observation, sort_keys=True, separators=(',', ':'),
                                                   ensure_ascii=False, allow_nan=False).encode('utf-8')).hexdigest()
    return dict(schema='observed-high-parameter-input-associations.v1',
                stage='high_function_after_decompilation', target_sha256=expected_target,
                function_address=expected_address, source_ir_sha256=evidence_sha256,
                source_observation_sha256=observation_digest, parameters=parameters,
                unbound_inputs=unbound, omitted_instances=omitted, complete=complete,
                unbound_input_observations=[dict(varnode=node['id'], space=node['space'],
                    offset=node['offset'], bits=node['size'] * 8,
                    unaffected=bool(node.get('unaffected')), persistent=bool(node.get('persistent')))
                    for node in inputs if node['id'] not in used],
                abi_recovered=False, source_parameter_count_proved=False, call_semantics_proved=False,
                limitations=['HighSymbol membership is a post-decompilation observation, not original source arity or ABI',
                             'no implicit inputs, register aliases, argument ordering or callee behavior are synthesized',
                             'complete covers observed parameter/input association inventory only, not call argument completeness'])
