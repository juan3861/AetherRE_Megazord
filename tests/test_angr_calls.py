from aether_re.adapters.angr import _call_targets


class _FakeFunction:
    # The old implementation inspected transition_graph.nodes(), which are
    # block nodes. This fake intentionally exposes unrelated block addresses.
    transition_graph = type("Graph", (), {"nodes": lambda self: [0x101, 0x102]})()

    def get_call_sites(self):
        return [0x110, 0x120]

    def get_call_target(self, site):
        return 0x200 if site == 0x110 else None


def test_angr_call_extraction_uses_callsite_api_not_basic_block_nodes():
    calls, unresolved = _call_targets(object(), _FakeFunction(), 0x100)
    assert calls == ["0x200"]
    assert unresolved == 1
