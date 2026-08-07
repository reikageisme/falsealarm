import hashlib

def calculate_signature(body: str) -> str:
    """
    Calculate a lightweight signature for an HTTP response body.
    This uses the simple algorithm: content-length + hash of first 64 bytes + hash of last 64 bytes.
    This is much faster than full simhash while still effectively grouping identical or nearly-identical pages
    (like parking pages or generic error pages).
    """
    if not body:
        return "0|empty|empty"
    
    length = len(body)
    
    # Take up to 64 bytes from start and end
    first_chunk = body[:64].encode('utf-8', errors='ignore')
    last_chunk = body[-64:].encode('utf-8', errors='ignore')
    
    h_first = hashlib.md5(first_chunk).hexdigest()[:8]
    h_last = hashlib.md5(last_chunk).hexdigest()[:8]
    
    return f"{length}|{h_first}|{h_last}"

def is_similar(sig_a: str, sig_b: str, length_threshold: float = 0.95) -> bool:
    """
    Check if two signatures are similar.
    For this lightweight signature, they are similar if:
    - The first and last chunks match exactly (meaning the header/footer structure of the page is identical).
    - The content lengths are within the threshold difference.
    """
    if sig_a == sig_b:
        return True
        
    parts_a = sig_a.split('|')
    parts_b = sig_b.split('|')
    
    if len(parts_a) != 3 or len(parts_b) != 3:
        return False
        
    len_a = int(parts_a[0])
    len_b = int(parts_b[0])
    
    # If the structure hashes (start/end) don't match, they aren't similar
    if parts_a[1] != parts_b[1] or parts_a[2] != parts_b[2]:
        return False
        
    # If structural hashes match, check if length is within tolerance
    if len_a == 0 and len_b == 0:
        return True
    if len_a == 0 or len_b == 0:
        return False
        
    ratio = min(len_a, len_b) / max(len_a, len_b)
    return ratio >= length_threshold
