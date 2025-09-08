from glaurung import similarity as sim


def test_cluster_single_linkage_basic():
    # Construct 3 similar digests and 1 outlier by deriving from a base
    base = "8:4:aa:bb:cc"
    d1 = base
    d2 = "8:4:aa:bb:cd"  # small change
    d3 = "8:4:aa:bb:ce"
    out = "8:4:11:22:33"  # different blocks
    clusters = sim.cluster_single_linkage(
        [d1, d2, d3, out], threshold=0.5, max_pairs=100
    )
    # Expect one cluster of size 3 and one cluster of size 1
    sizes = sorted(len(c) for c in clusters)
    assert sizes == [1, 3]
