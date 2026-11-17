"""Observed stack-value transport, portable own sum6 High IR. No binary execution."""
import base64,zlib,json,copy
import pytest
from aether_re.stack_parameters import prove_ms_x64_stack_values
CASES=json.loads(zlib.decompress(base64.b64decode('eJztWl1vpDYU/S88Zyv8DXmrtH2o1A+p2j6tImRsM0GdgSkws7uN8t/rCwwGJ5OESUNmk0YKEozxuefea1+4h883wbYqs3xtgsvgdx1cBHkVXN4Etbo2G2mvra5zXckP1/nq+sNWldr8sEd2VCOrlWmS+lpixu0wrjIdMpppRsKMYSIVJhniIhSh4cYQjJFAiGeGcaJikxGjU5RiHXIlTZymdspsV6gmL4tEal2ZurazVnJziaIwDJGdxw6prU1Fk6vE/L3L93JtCmUSa//e6OAyk+vaXARpXsjqW3IYWieVUXZANRpSVvnKjlondbmr7Ax3R5iisXOk61L9Zc1IAVuVm+3aNNZPTbUDHPjRGvn5Jsj1YVBt/dLcZ3hTbqeX09he3lpMoyzXsoKZruzAnZqcl1tTSfAKnAclzFWC/0sMBwIHCgcGBw4HAYcIDnE7OAyubv2JepO76dqo2rOff/uU/PrnL59aP/+9A99CJmzV1PAI8Jp8Y39EEfhSG5sx4a3NnGK7a1o794SAkXtmwe2QXWN/sLPsaRTcXhzAkQ/+48ePj2FnAzZ22MjHBlqANcEWbISNTyAeswGc4gEc++Aw9R4hNkVHiIzgyXzqcerQ4wGdTNEF68CJB26NcuD0FO5mQOeOO/W5kxZeeFFHfBx2Np+7dCnHHXc2RUe957kXdxSJETo/gbwUA3zkyHOfPBi5x9gLPMbjwIsTyGuH7sgLj3wkOnQv8piOIx+dQL7d1vrlHjr2kc++zTwceaHHYhz6eD77lI/gHf14Cg80Lzq0KXw8jj2abHd//PTpzz9+eww+dvCj3Q752x2OWnwL1262e1kVFmW01fY7Yr2VABRUZpXXjZ3qIvgrL/T0SplltQH7W4Pr/B8IfY93qD5ZZcxQrezWXsPNRTNc2hUyy4xqRjUNymrS5MOVwTGwTTvTlC0RjbOrPbWVdGwXucesHqSzq7PxuWbRaLbH7nPYxLJneewi0CbLixzKaFc+nbFd1ZlnbbRMeNuq8HzLXs6PaOJHPN/ahdYJVPVZC4Uts1Cg4J93hEdVqC/U57yuySQfT/DtQgsbiZkbt1goH/n8nXvZfKTjfGyfnc45H9kkH+nIWhth+4Y6mHo4HezEL5WJMIczCp56ZyViukwiwvPweSciH4W2e4o950QUk0RkMxKRvFSJ9hIxmrkj6oUSUZz7jhiNEzE+9x0xHicijubF/FFTnxXzK2gVFo352sAL5VoWq51cmaS19WvEL3/56ZLTS0tH7tZgFvQV87WpknprVDfsi7W9/FIH0IfUuQTG67xp1tCE6ZujSZrDuyenlsEG5k9lbcbvrvB3cEv3HlrITT/CXgccSsjgp43ZlNW3ANqnh3m/2JfdpPMTAm8f7nfBh0kYje7Li24ago9Oc4hTa0h0X7weteSwybRmkDt7z5H7r27tuzu0sydt7jKtTbU3um90S+slY5nUXbfbTrkCRPgxcX3qzI5ItOki2DZXg9fqjMs0v6eN3fe3BzqJKndF43fMlVyvR/1y71fnizaLrCuhdR5chnBjY1Y2bRLrePO1vdSHpr0paYWCb1uT9FfXZbGC/8n6q515h5V3nWttCsun2VXFYEhzDWPLvGhHHi7C9NCJP9SCzgTvUt4mVbsQbgK5lzZa6XpY6E3ZACFkt4iNXWZwm2VyyIihpwyJM+KP7vJHHn/8hvgjnz++yx97/Mkb4o99/uQuf+Lxp2+IP/H507v8qcefvSH+1OfP7vJnHn/+hvgz4H9lS6fZ57prlwcy1IpEWqk4pGGIQzuKkzQOM1vcCNZaC4mQFqmWaWQEVoKnkaSKh8pIE2Vd228kP8N+eaL8bMIwzdIYK4siFbPl1aQRZSTGzJZfIhSXAokYixRJnYo4IoqxiHLCIql59liRxeo7lZ97w335GRt4wv8O5eeOTy+H8WPyMyadHuNrwJiFDwnQT4F3UqRTo5CvRrXiN+a+Fvc8ARor6aiLYwI0JnELzpBP/XkCNFZOAkZHBWjcSkkt2ASdoYcE6MfBNRrAR8I/9f3eYhPhCf/iIfX5CX7XLubEgTMfvGWOQi/qKKQPyc9PoB4N6JQdU58Z6sCpB/6w+PwU7u6zA+a4i3vlV8S9nEMsfkh9fpy7cWHnjrunPYtW+ka+9I2eKT1j48Iu6DHlGShedGDT5TYJ+3zludug+8VOjgrPuNfdIfBHhOduLzxP4RnTma2bhZRnPFHEd0Vu4+QMG85H/nINl1dRn7uSc26qAJ8X3KVEAfrfrIdl9PCunp+nHo4ZmhfhhfRwePw4Yfm+niTO5n8bFL+eJA5PWOf6qct8yxZe23Sya5/wzdBS3xaEM3fvpb4tCOdv36+n1qMTBOiFV/ZxBfpMNF14rThHTbd79D/nTBzL9egEBXrhrXEiQZ/9Mo8nFXHm9y//S9BvQ4IeniVhDhyjuw+Zj1rxnajYizTY/1exX1TFaVuj71jFhlbYe1axoZfwnlVseN96zyo2dAnfs4oNrzf3qdiCYMSIygjDcWhEZEKkjMqkyVCobG2LU04o1TjlMREoY0ZrFmU0THEUmzC4vfoXfXndWA==')))

def proof(case):
 return prove_ms_x64_stack_values(case['ir'],case['high'],evidence_sha256=case['evidence'])

@pytest.mark.parametrize('case',CASES,ids=['Od','O2'])
def test_actual_six_formals_are_values_and_observation_bound(case):
 result=proof(case)
 assert result['formal_count']==6
 assert [v['offset'] for v in result['stack_inputs']]==[40,48]
 assert [v['ordinal'] for v in result['stack_inputs']]==[4,5]
 assert result['abi_recovered'] is result['source_parameter_count_proved'] is result['binary_equivalence_proved'] is False

@pytest.mark.parametrize('mutation',['compiler','endian','language','offset','width','hidden','this','unbound','memory','pointer','overlap'])
def test_bad_or_ambiguous_stack_transport_refuses(mutation):
 case=copy.deepcopy(CASES[0]);data=case['ir'];high=case['high']
 stack=next(v for v in data['varnodes'] if v['kind']=='stack' and v['input'])
 if mutation=='compiler':data['context']['compiler_spec_id']='gcc'
 if mutation=='endian':data['context']['endian']='big'
 if mutation=='language':data['context']['language_id']='ARM:LE:64:default'
 if mutation=='offset':stack['offset']='0'
 if mutation=='width':high['parameters'][4]['size']=4
 if mutation=='hidden':high['parameters'][4]['hidden_return']=True
 if mutation=='this':high['parameters'][4]['this_pointer']=True
 if mutation=='unbound':high['parameters'][4]['instances']['observed']=[];high['parameters'][4]['instances']['total']=0
 if mutation=='memory':data['operations'][0]['opcode']='LOAD'
 if mutation=='pointer':high['parameters'][4]['type_name']='unsigned long long *'
 if mutation=='overlap':
  output=next(v for v in data['varnodes'] if v.get('definition'))
  output.update(kind='stack',space='stack',offset=stack['offset'])
 with pytest.raises(ValueError):proof(case)
