"""Own portable High IR; observations synthesized for validation, not producer proof."""
import base64,zlib,json,hashlib,copy
import pytest
from aether_re.indirect_effects import validate_indirect_effects
DATA=json.loads(zlib.decompress(base64.b64decode('eJzlXFtvo0YUfq/U/xD5eVsxFzDkLc1G6kppss1mpVZVZWEYErQOuICzvWj/exliG2Z88BnbE8eW8xIDY5jvO5f55szg/77/7uxsUEaP4ikcnJ8NHh7TuAh/eEwfHn+YRnksfnwmg3dNoyosHkQ1Kh9D6nqyrRclsePyJHaZk7iUhRFlCfGGztARnhCMUjIkxEuE67EoEAkT8ZiMaex4USiC8Xh+32SWRVWaZ6MwjgtRlvLWRfh0TnzHcQihzrxdWXcxq9JoJP6apc/hRGSRGE2L/FnE9VeScFKKl4bjNAuLf0aL9uWoEFHdqtDb5UX6UDedjMp8VtT36mkmsqq+23iSR19k18aL/kT503QiKlGfrIrZ4tmymYTwhzw8O/vv5V99JY27325OlTWlVQ/ceYN8ql3nSef6tO6siGrO8qJ55p+dr86izoXF6U6HmlYtKtLetrmysPYklz102mvfFh87D8unogilDbWHDXKne9tBTtRDqh4y9ZCrh6566KmHw8GyXy8fvr3rsQBBLODy9RZQrusWwIl2NKLnzgcQ/Q6/GTO+GWC1TV2EGrvIFj3fyN+a6Bzls0rv10BG4vJC5xlrXNRXHSnQPFb3YM2FiebDRHNiwo0dk2KO6a13TC/ayTH1DLCDLxmlBqIFNNEimpiHNHvbkF7PHLEbhesTNfKwNdbQwoBocUC1OKB6KtfigGpxQLVsTjXrU836dKgda/2jWv+Ys+It8t+f86EewK17UXesqr8gxY88/fH+7tPnn7r+U+sPqT3qix0bDaaR5lQsVHpYpU/yK4QPlX4XsSi64dXmzkGaTWeVbqhnpjH3zIedFNNBMKumL3nwedmgL4C643IH+oeb9x/uri7vtwGfgOAZh8ATY/B8SDTwvoeA58zD0NN9oQdNTzdAT3X0Qww9dzH0DER/eXF9bQ05IxBwZgzcV5ODdGjlmHJXP4G5BXVRYrjdfMA5nA98iBu+Sz7AsC+9phe6C/vE7cfftwEORwMPIOCuMfDWgr3OPwwwoN4egLqg93vm3o8GuU8wnMPXx8k8CObQGGaAwQzQRO6DKH/5fH3/4erXzxfbJDQXjloGOq/5KM71jMW5j1nZ7QqU6WM66leq2jRTKuTlzREOg/1xCDrMBmKAacMCZwE6HJJ9cEhgKfkaJBJnR03hrygqipDInP2QCIvS1yDRAaPZXJ/IgUYj0cH0R+DvhURY274KiaC6NRcygRbNxGEoh3QvHMIK+cPN/ejm9t4ui/AUYQNRFFCdRcwTAx+dHcJK+PKnu4uby5/tYQeVsLlOIo6WygLf3Maw4pU2/u32bguIngNB9OiuskHP1i5mXuKh4pBYVcEeA5GDKdZ8sG9h9ALFVTCBZfDd1f3nu5ttoEYQVB+Eaj4kU860GPaJuSPDGvjy4tM2hYyeVO+y3dxYKoj1xuQ+Q40JK1UZshfv31sDy8HZ2wYq1detSbCQ5T5asKOwwrRsZrBat4m2xCqTxEEHHwrLwI/3d1atDM5FzBWgIucaK2sF8FojYhM8QtEERmE5d317YY8KF5xRmOs47mtU0ABFziiKvK9MadXh3d3Ul0leQ8uOFFZbO5Sj++bfIFpzvbUqRnx0/s3QihztU2LW4YNy07xepdRjmhMBmtg5nu5gLfbp/vbuyl6IgzLUN4cerFheK2e1EY1LFmq1ONkX2mBWC4wht8m5P7Qd1Lg94swuUtC4xFydtYNyP1Q8X+9HncF1WGIuz1YmzAwt3bSFif41NVieWZ4wwzKcmAs0wteumj+HRVb3fM2aubr6NCinYYNlUIiHtKzq7rTXvqRZ3HMpT5JSNNyqu9/Sf5vplIZi0Nlv15xNCiHbtVv2XjgURSkflFWr12ZZmCQiqpqtfurN5CbEUZW2mwDXW7pZfQcIiPKsrAD0zfkwq0D0ifIX+0ZcaNDmZKigjLnQrm1KBszFLEtrLwfIWLnQUhFEjpkrwPC39QUMf3spFkmapXJLSRPwWOpXdy603NTOEH0BqNHP9zlJZOYkVgNmDUnyORgRvmctYEiyip4fdogoi1Z794O9RYtKrhYs2DRX3ehij6T4DUaXXYNleNLBwkF1sSc/OIxgwZT2M5xPa/EIMPQknvLiH9g9GqXpRLtw8zZeQmEv2VaDHtaIakYA7AJbEkAOK00aMeBadYEDyw/rpSc2GW02BL7OFGUn1fE2yQIeUE9hioKtKam7WHbjhjjyz6XHxA9WmFe3StngxzsqfrDdl3IDpzWtenwqJLA6Bh/YdG69Z2DbyZt1j5PX8Xh+UTb4niZL2PpYs4L4CiQdVf2E4kM5f8tq42GwhK00N6tYdsfz8LDoWZ+1KRpr6kbvncc0dmDes54egpf0fTBf76CXj8t/0GFf3eO+u/8c2ECG+A9a5ZbryKcqGSmandXN/afFDkGLvsQBc89Wk60jnGuBeWWbxEs9H6rikMN1DbTcR3pG7e0WBLRfHdmQnrdxD/muwMmmDnSaSeAy1knUyglaxFJevji5xKq8rGBD0g6PqsRJ0CkRIfbGXXKE7mFtg9fcPY5qxkNQ0Sq3ztpSJpQd1/oSRSfMyjsxpxc8Q9A3TgQ9odYWz6gzPrLIwDe8+RZ9Ywx4x4Fv9JKvi1jzjuS4ZnQUnewrb9fYGHb9o1JlFN/h4oOLQluFD+NHFz3yxbOThg8OLSeTPBm8DmFhf1cCbBk+dJ3BQTK2rn4B4XAg1S/5b/6iVm3SSvwt7zvnYzAJs4dZ+CBGL7T87Xvn11fnHj+vc2s4myyN3/yKeToRxaicimje+mtNT/61XLYRWZyGTS6epFU1WY4sg/kvto/GafNumbcIlEH6JJ89DssF+S8vssm/5Zcb2yivpHVfgcvCp1XDLczMmfLmW58560t6z5qTX/MiHi2MuTjfviwHdmOlBLboi6v+gGN/zaztDaM79kYL7SUtYE9W490iL7rUWHSFBgTqC9DcFifaHoaleUBPWW28ASEvH5r3JevP3/4HTfnLkA==')))
EVIDENCE=hashlib.sha256(json.dumps(DATA,sort_keys=True).encode()).hexdigest()
def observation():
 nodes={n['id']:n for n in DATA['varnodes']};rows=[]
 for op in DATA['operations']:
  if op['opcode']!='INDIRECT':continue
  reference=nodes[op['inputs'][1]];ref=int(reference['offset'],16)
  effect=next(o for o in DATA['operations'] if o['sequence']['time']==ref)
  rows.append(dict(operation=op['id'],reference_varnode=reference['id'],reference_id=ref,status='resolved',effect=dict(operation=effect['id'],opcode=effect['opcode'],sequence=effect['sequence'])))
 return dict(schema='observed-indirect-effects.v1',stage='high_function_after_decompilation',target_sha256=DATA['target_sha256'],function_address=DATA['function_address'],source_ir_sha256=EVIDENCE,total=len(rows),resolved=len(rows),unresolved=0,complete=True,entries=rows,alias_semantics_proved=False,call_semantics_proved=False)
def validate(value,data=None):
 return validate_indirect_effects(value,data=data or DATA,expected_target=DATA['target_sha256'],expected_address=DATA['function_address'],evidence_sha256=EVIDENCE)
def test_resolved_inventory_does_not_prove_alias_effects():
 value=observation();assert validate(value) is value
 assert [r['effect']['opcode'] for r in value['entries']]==['CALL','CALL','STORE','STORE']
 assert value['alias_semantics_proved'] is value['call_semantics_proved'] is False
@pytest.mark.parametrize('status',['unavailable','outside_inventory'])
def test_unresolved_is_preserved(status):
 value=observation();value['entries'][0].update(status=status,effect=None)
 value.update(resolved=3,unresolved=1,complete=False)
 assert validate(value) is value
@pytest.mark.parametrize('mutation',[
 lambda v:v.update(target_sha256='0'*64),lambda v:v.update(function_address='ram:1'),lambda v:v.update(source_ir_sha256='0'*64),
 lambda v:v.update(total=True),lambda v:v.update(total=3),lambda v:v.update(resolved=3),lambda v:v.update(unresolved=1),lambda v:v.update(complete=False),
 lambda v:v.update(alias_semantics_proved=True),lambda v:v.update(call_semantics_proved=True),lambda v:v.update(extra=1),
 lambda v:v['entries'].append(v['entries'][0]),lambda v:v['entries'].pop(),lambda v:v['entries'].reverse(),
 lambda v:v['entries'][0].update(operation='o3'),lambda v:v['entries'][0].update(reference_varnode='v471'),
 lambda v:v['entries'][0].update(reference_id=52),lambda v:v['entries'][0].update(reference_id=True),
 lambda v:v['entries'][0].update(status='invented'),lambda v:v['entries'][0].update(effect=None),
 lambda v:v['entries'][0]['effect'].update(operation='o26'),lambda v:v['entries'][0]['effect'].update(opcode='STORE'),
 lambda v:v['entries'][0]['effect']['sequence'].update(pc='ram:1'),lambda v:v['entries'][0]['effect']['sequence'].update(time=52),
 lambda v:v['entries'][0].update(extra=1),lambda v:v['entries'][0]['effect'].update(extra=1),
])
def test_false_identity_counts_and_resolution_are_rejected(mutation):
 value=copy.deepcopy(observation());mutation(value)
 with pytest.raises(ValueError,match='indirect_effect_observation_invalid'):validate(value)
def test_unresolved_status_cannot_hide_a_resolved_payload():
 value=observation();value['entries'][0]['status']='unavailable';value.update(resolved=3,unresolved=1,complete=False)
 with pytest.raises(ValueError,match='indirect_effect_observation_invalid'):validate(value)
def test_range_status_requires_out_of_range_reference():
 value=observation();value['entries'][0].update(status='reference_out_of_range',effect=None);value.update(resolved=3,unresolved=1,complete=False)
 with pytest.raises(ValueError,match='indirect_effect_observation_invalid'):validate(value)

def test_empty_resolution_inventory_is_not_an_alias_claim():
 from pathlib import Path
 import runpy
 f=runpy.run_path(str(Path(__file__).with_name('test_ghidra_pcode_ir.py')))
 data=f['scalar_ir']();value=observation()
 value.update(target_sha256=f['TARGET'],function_address=f['ADDRESS'],entries=[],total=0,resolved=0,unresolved=0)
 assert validate_indirect_effects(value,data=data,expected_target=f['TARGET'],expected_address=f['ADDRESS'],evidence_sha256=EVIDENCE) is value
 assert value['complete'] and not value['alias_semantics_proved']

def test_explicit_out_of_range_reference_is_unresolved():
 data=copy.deepcopy(DATA);value=copy.deepcopy(observation())
 first=next(n for n in data['varnodes'] if n['id']==value['entries'][0]['reference_varnode'])
 first.update(size=8,offset='100000000')
 value['entries'][0].update(reference_id=1<<32,status='reference_out_of_range',effect=None)
 value.update(resolved=3,unresolved=1,complete=False)
 assert validate(value,data) is value
