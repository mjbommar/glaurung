import glaurung as g


def test_ctph_hash_bytes_and_similarity_basic():
    data = b"A" * 2048
    h1 = g.similarity.ctph_hash_bytes(data)
    assert isinstance(h1, str)
    assert h1.startswith("8:4:")

    # Identical should be 1.0 similarity
    h2 = g.similarity.ctph_hash_bytes(data)
    s = g.similarity.ctph_similarity(h1, h2)
    assert 0.99 <= s <= 1.0

    # Small mutation should reduce, but remain > 0
    data2 = bytearray(data)
    data2[100] = ord("B")
    h3 = g.similarity.ctph_hash_bytes(bytes(data2))
    s2 = g.similarity.ctph_similarity(h1, h3)
    assert 0.0 <= s2 <= 1.0
    assert s2 <= s


def test_ctph_hash_path_roundtrip(tmp_path):
    p = tmp_path / "sample.bin"
    content = b"hello world" * 128
    p.write_bytes(content)
    h_file = g.similarity.ctph_hash_path(str(p))
    h_mem = g.similarity.ctph_hash_bytes(content)
    # Hashes for same content should match
    assert h_file == h_mem


def test_ctph_recommended_params():
    small = g.similarity.ctph_recommended_params(1024)
    mid = g.similarity.ctph_recommended_params(128 * 1024)
    big = g.similarity.ctph_recommended_params(4 * 1024 * 1024)
    assert small != mid != big


def test_ctph_matrix_and_topk():
    import random

    base = bytearray(b"A" * 4096)
    digests = []
    for i in range(6):
        buf = bytearray(base)
        # introduce a small mutation
        for _ in range(i):
            pos = random.randint(0, len(buf) - 1)
            buf[pos] = (buf[pos] + 1) % 256
        digests.append(g.similarity.ctph_hash_bytes(bytes(buf)))

    mat = g.similarity.ctph_pairwise_matrix(digests, max_pairs=1000)
    assert len(mat) > 0
    q = digests[0]
    top = g.similarity.ctph_top_k(q, digests[1:], k=3, min_score=0.1)
    assert 1 <= len(top) <= 3
