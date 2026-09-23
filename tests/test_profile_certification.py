from aether_re.profile_certification import certify_static_profile
def test_certificate_is_fail_closed_without_oracle_relations():
 r=certify_static_profile({'schema':'profile-scope.v1','profile_id':'wasm'},{'blind_hash':'a','calibration_hash':'b'},{'workers':[]},{'entities':{},'relations':{'status':'unmeasured'},'oracle_independent':False},{'regressions':[]})
 assert r['status']=='NAO_COMPROVADA'
 assert {'relations_unmeasured','independent_oracle_missing'} <= {x['code'] for x in r['errors']}
