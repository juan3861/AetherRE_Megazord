import zipfile,pytest
from aether_re.static_profiles import detect_static_profiles,select_static_profile
def test_zip_profile_and_ambiguity(tmp_path):
 p=tmp_path/'apk.bin'
 with zipfile.ZipFile(p,'w') as z:z.writestr('AndroidManifest.xml','x');z.writestr('classes.dex',b'dex\n035\0')
 assert detect_static_profiles(p)[0].profile_id=='android-apk'
 with zipfile.ZipFile(tmp_path/'mixed.zip','w') as z:z.writestr('classes.dex','x');z.writestr('A.class',b'\xca\xfe\xba\xbe')
 with pytest.raises(ValueError,match='profile_ambiguous'):select_static_profile(tmp_path/'mixed.zip')
