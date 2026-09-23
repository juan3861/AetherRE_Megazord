from aether_re.adapters.wasm import normalize_wasm
def test_wasm_preserves_loss_when_names_absent():
 assert 'function_names' in normalize_wasm({'functions':[]},'sha256:x','ev:w').losses
