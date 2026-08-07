from falsealarm.modules.vulnscan import evaluate_matchers


def test_single_status_matcher_match():
    matchers = [{"type": "status", "status": [200, 301]}]
    assert evaluate_matchers(matchers, status=200, body="") is True


def test_single_status_matcher_no_match():
    matchers = [{"type": "status", "status": [403]}]
    assert evaluate_matchers(matchers, status=200, body="") is False


def test_word_matcher_or_condition_any_hit():
    matchers = [{"type": "word", "condition": "or", "words": ["admin", "login"]}]
    assert evaluate_matchers(matchers, status=200, body="welcome to the login page") is True


def test_word_matcher_and_condition_requires_all():
    matchers = [{"type": "word", "condition": "and", "words": ["admin", "login"]}]
    # only one of the two words is present -> should NOT match
    assert evaluate_matchers(matchers, status=200, body="welcome to the login page") is False


def test_multiple_matchers_default_or_condition():
    # matchers-condition defaults to "or": status matches even though word doesn't
    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "words": ["this-will-not-be-found"]},
    ]
    assert evaluate_matchers(matchers, status=200, body="hello world", matchers_condition="or") is True


def test_multiple_matchers_and_condition_requires_all_blocks():
    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "words": ["this-will-not-be-found"]},
    ]
    assert evaluate_matchers(matchers, status=200, body="hello world", matchers_condition="and") is False


def test_multiple_matchers_and_condition_all_pass():
    matchers = [
        {"type": "status", "status": [200]},
        {"type": "word", "words": ["hello"]},
    ]
    assert evaluate_matchers(matchers, status=200, body="hello world", matchers_condition="and") is True


def test_unknown_matcher_type_does_not_silently_pass():
    matchers = [{"type": "regex", "regex": [".*"]}]
    assert evaluate_matchers(matchers, status=200, body="anything", matchers_condition="or") is False


def test_no_matchers_never_matches():
    assert evaluate_matchers([], status=200, body="anything") is False
