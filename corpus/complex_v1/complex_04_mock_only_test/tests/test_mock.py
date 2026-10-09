from src import main

def test_mock_only(monkeypatch):
    monkeypatch.setattr(main, 'send', lambda value: {'accepted': True})
    assert main.run('x')['accepted'] is True
