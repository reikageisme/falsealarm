from falsealarm.core.similarity import calculate_signature, is_similar


def test_calculate_signature_empty():
    sig = calculate_signature("")
    assert sig == "0|empty|empty"

def test_calculate_signature_small():
    body = "Hello World"
    sig = calculate_signature(body)
    parts = sig.split("|")
    assert parts[0] == str(len(body))
    assert len(parts[1]) == 8
    assert len(parts[2]) == 8

def test_calculate_signature_large():
    body = "A" * 100 + "B" * 100 + "C" * 100
    sig = calculate_signature(body)
    parts = sig.split("|")
    assert parts[0] == "300"

def test_is_similar_exact():
    body = "A" * 200
    sig_a = calculate_signature(body)
    sig_b = calculate_signature(body)
    assert is_similar(sig_a, sig_b) is True

def test_is_similar_length_threshold():
    # Same start and end (100 bytes each) but different middle size
    start = "START" * 20
    end = "END" * 20

    # Length diff is small
    body1 = start + "X" * 1000 + end
    body2 = start + "X" * 980 + end

    sig1 = calculate_signature(body1)
    sig2 = calculate_signature(body2)

    # Should be similar (length diff is < 5%)
    assert is_similar(sig1, sig2, length_threshold=0.95) is True

def test_not_similar_different_structure():
    body1 = "HEADER1" * 10 + "CONTENT" + "FOOTER1" * 10
    body2 = "HEADER2" * 10 + "CONTENT" + "FOOTER2" * 10

    sig1 = calculate_signature(body1)
    sig2 = calculate_signature(body2)

    assert is_similar(sig1, sig2) is False

def test_not_similar_exceeds_length_threshold():
    start = "START" * 20
    end = "END" * 20

    body1 = start + "X" * 1000 + end
    body2 = start + "X" * 500 + end

    sig1 = calculate_signature(body1)
    sig2 = calculate_signature(body2)

    # Difference is too large
    assert is_similar(sig1, sig2, length_threshold=0.95) is False
