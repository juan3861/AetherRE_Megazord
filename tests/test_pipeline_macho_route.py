def test_macho_route_is_explicit_in_pipeline():
 import inspect
 from aether_re import pipeline
 assert "'macho': [RizinAdapter()]" in inspect.getsource(pipeline.run_megazord)
