from aether_re.adapters.android import AndroidAdapter

def test_android_adapter_fails_closed_when_pinned_tools_are_missing(tmp_path):
 adapter=AndroidAdapter(java=str(tmp_path/'java.exe'),jadx=str(tmp_path/'jadx.jar'),apktool=str(tmp_path/'apktool.jar'))
 assert adapter.available() is False
 assert adapter.analyze(tmp_path/'target.apk',tmp_path/'out')['error']=='android_workers_unavailable_or_hash_mismatch'

def test_android_component_parser_is_conservative(tmp_path):
 manifest=tmp_path/'AndroidManifest.xml';manifest.write_text('<manifest><application android:name="x.App"><activity android:name="x.Main"/></application></manifest>')
 assert [x['name'] for x in AndroidAdapter._manifest_components(manifest)]==['application:x.App','activity:x.Main']
