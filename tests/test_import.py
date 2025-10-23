import imtrackerweb


def test_has_run() -> None:
    assert hasattr(imtrackerweb, "run")
    assert callable(imtrackerweb.run)
