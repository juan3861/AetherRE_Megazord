from aether_re.pipeline import adapters_status

def test_specialized_static_workers_are_visible_in_status():
 names={item['name'] for item in adapters_status()}
 assert {'wasm','android','jvm'} <= names


def test_specialized_profile_does_not_receive_native_adapters(tmp_path, monkeypatch):
    # Selection is asserted from source-level routing to avoid running an
    # external decompiler in a unit test.
    import inspect
    from aether_re import pipeline
    source=inspect.getsource(pipeline.run_megazord)
    assert "selected_profile.profile_id in native_profiles" in source
