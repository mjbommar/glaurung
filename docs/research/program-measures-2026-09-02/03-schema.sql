-- ============================================================================
-- Proposed Glaurung function identity + index schema (SQLite)
--
-- Design rule inherited from the existing table: identity is `(scheme, value)`,
-- never a column per algorithm. What is added below is (a) a *payload* side,
-- so a match can carry a name/prototype/comments the way Lumina and WARP do,
-- (b) a *library* side, so a match can say WHICH libc it came from the way
-- Ghidra FID's LibrariesTable does, and (c) index tables that make the
-- non-exact schemes queryable.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 0. Existing table, unchanged. Exact-identity schemes only.
--    Match semantics: equality on (scheme, identity). Ambiguity is real and
--    must be resolved by the caller (Glaurung already refuses to port an
--    annotation when either side is non-unique).
--    Schemes that belong here:
--      'glaurung-structural-v1'  16-hex SHA-256 over normalized tokens + CFG
--      'warp-function-guid-v1'   UUIDv5 over sorted relocation-masked BB GUIDs
--      'fid-full-hash-v1'        64-bit FNV-1a over opcode-masked code units
--      'fid-specific-hash-v1'    ...plus small non-address constants
--      'lumina-md5-v1'           MD5 over calcrel()-masked basic blocks
-- ---------------------------------------------------------------------------
-- CREATE TABLE function_identity (
--     binary_id INTEGER NOT NULL, entry_va INTEGER NOT NULL,
--     scheme TEXT NOT NULL, identity TEXT NOT NULL,
--     n_blocks INTEGER, set_at INTEGER,
--     PRIMARY KEY (binary_id, entry_va, scheme));

-- Add the two size counters FID and BSim both need for thresholding.
-- (n_blocks alone cannot express "how many scoreable instructions".)
ALTER TABLE function_identity ADD COLUMN n_units INTEGER;   -- code units, calls excluded
ALTER TABLE function_identity ADD COLUMN n_bytes INTEGER;   -- body size

-- ---------------------------------------------------------------------------
-- 1. Signature LIBRARIES. The provenance side, modelled on Ghidra FID's
--    LibrariesTable (name / version / variant) with WARP's Target bolted on.
--    `variant` carries the compiler settings that change hashes but are not
--    part of the source version -- the field FID explicitly reserves for it.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siglib (
    siglib_id     INTEGER PRIMARY KEY,
    name          TEXT NOT NULL,          -- 'glibc', 'libstdc++', 'openssl'
    version       TEXT,                   -- '2.39'
    variant       TEXT,                   -- 'gcc-13.2 -O2 -fPIC'
    architecture  TEXT NOT NULL,          -- WARP Target.architecture
    platform      TEXT,                   -- WARP Target.platform
    source_sha256 TEXT,                   -- the .a / .so we built it from
    ingest_date   INTEGER,
    UNIQUE (name, version, variant, architecture, platform)
);

-- ---------------------------------------------------------------------------
-- 2. Library-side function records: the thing we MATCH AGAINST.
--    Separate from `function_identity` (which is per-observed-binary) because
--    a library entry has no binary_id/entry_va and does have a payload.
--    Deduplicated on identity the way BSim dedups `vectable` rows: `occurrences`
--    is Lumina's "popularity" and BSim's `vectable.count`, and it is the
--    cheapest false-positive signal available.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siglib_function (
    sigfn_id     INTEGER PRIMARY KEY,
    siglib_id    INTEGER NOT NULL REFERENCES siglib(siglib_id),
    scheme       TEXT NOT NULL,
    identity     TEXT NOT NULL,
    name         TEXT NOT NULL,           -- mangled, as found
    base_name    TEXT,                    -- demangled, namespace+underscores stripped
                                          -- (FID groups Multiple Matches on exactly this)
    n_units      INTEGER,                 -- scoring weight; FID's code_unit_size - callCount
    n_bytes      INTEGER,
    prototype    TEXT,                    -- WARP Function.type / Lumina prototype
    payload      BLOB,                    -- CBOR: comments, stack vars, calling convention
    occurrences  INTEGER NOT NULL DEFAULT 1,
    UNIQUE (siglib_id, scheme, identity, name)
);
CREATE INDEX IF NOT EXISTS idx_siglib_function_lookup
    ON siglib_function(scheme, identity);
CREATE INDEX IF NOT EXISTS idx_siglib_function_basename
    ON siglib_function(base_name);

-- ---------------------------------------------------------------------------
-- 3. FLIRT-style MASKED signatures. Cannot live in `identity TEXT`: matching is
--    a masked-prefix walk, not equality, so it needs its own table and its own
--    index. Fields are FLIRT's, one-for-one (lancelot-flirt's FlirtSignature).
--
--    MATCH SEMANTICS (four escalating levels, exactly IDA's):
--      L1  index seek on `prefix_key` = the first `PREFIX_KEY_LEN` (8) bytes with
--          masked positions forced to 0x00 AND `prefix_key_mask` equal, then
--          verify `pattern & mask == candidate & mask` over all `pattern_len`
--          bytes. Replaces IDA's trie: an 8-byte B-tree key does the same
--          prefix narrowing a trie node does, and SQLite already has the B-tree.
--      L2  if >1 survivor: CRC16 over `crc_len` bytes starting at `pattern_len`.
--      L3  if >1 survivor: `tail_offset`/`tail_byte` single-byte discriminator.
--      L4  if >1 survivor: every row in `siglib_reference` for the candidate must
--          resolve, at the given offset, to a symbol with that name. Recursive
--          and multi-pass -- defer and re-run after other names are assigned.
--      A survivor set >1 after L4 is a genuine COLLISION: report all names, do
--      not pick one. (IDA hands this to a human via an .exc file.)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siglib_flirt (
    sigfn_id        INTEGER PRIMARY KEY REFERENCES siglib_function(sigfn_id),
    pattern_len     INTEGER NOT NULL,     -- normally 32
    pattern         BLOB NOT NULL,        -- masked positions stored as 0x00
    mask            BLOB NOT NULL,        -- 1 bit per byte, MSB-first; 1 = fixed
    prefix_key      BLOB NOT NULL,        -- pattern[0..8], masked bytes zeroed
    prefix_key_mask INTEGER NOT NULL,     -- the 8 mask bits, so 0x00 != wildcard
    crc_len         INTEGER NOT NULL,     -- FLIRT: bytes fed to CRC16, max 0xFF
    crc16           INTEGER NOT NULL,
    func_len        INTEGER,              -- FLIRT size_of_function, max 0x8000
    tail_offset     INTEGER,              -- L3 discriminator, NULL if unused
    tail_byte       INTEGER
);
CREATE INDEX IF NOT EXISTS idx_siglib_flirt_prefix
    ON siglib_flirt(prefix_key, prefix_key_mask);

-- FLIRT's `^offset name` reference names AND WARP's constraints are the same
-- shape: (referrer, offset, referent). One table serves both.
--   kind='flirt-ref'  referent_name is a symbol that must be present at offset
--   kind='warp-call'  referent_guid is a callee function GUID at that offset
--   kind='warp-adj'   referent_guid is an adjacent function; offset may be < 0
--   kind='fid-child' / 'fid-parent'  Ghidra FID RelationsTable edges
CREATE TABLE IF NOT EXISTS siglib_reference (
    sigfn_id      INTEGER NOT NULL REFERENCES siglib_function(sigfn_id),
    kind          TEXT NOT NULL,
    offset        INTEGER NOT NULL,       -- signed; WARP uses i64::MAX for "unrelated"
    referent_name TEXT,
    referent_guid TEXT,
    PRIMARY KEY (sigfn_id, kind, offset, referent_name, referent_guid)
);
CREATE INDEX IF NOT EXISTS idx_siglib_reference_referent
    ON siglib_reference(referent_guid);

-- ---------------------------------------------------------------------------
-- 4. BSim-style sparse weighted FEATURE VECTORS.
--    Storage follows BSim exactly: the vector is deduplicated and refcounted
--    (`vectable.count`), and description rows point at a shared vector id.
--    `features` is the LSH_ITEM array {u32 hash, u16 tf, u16 idf} packed
--    little-endian, sorted ascending by hash so intersection is a merge.
--
--    MATCH SEMANTICS: weighted cosine similarity (BSim's `sim`, threshold 0.7)
--    plus a log-likelihood-ratio confidence (BSim's `sig`). Report BOTH: the
--    similarity says "how alike", the confidence says "is this a coincidence",
--    and BSim's documented calibration (10 -> 1/4000, 26 -> 1/100k, 43 -> 1/1e6,
--    93 -> 1/1e9) is only meaningful on the confidence.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feature_vector (
    vector_id   INTEGER PRIMARY KEY,
    vector_hash INTEGER NOT NULL UNIQUE,  -- exact-dup fast path (BSim H2 vec_hash)
    n_features  INTEGER NOT NULL,
    norm        REAL NOT NULL,            -- precomputed ||v||, so cosine is a dot
    weights_id  TEXT NOT NULL,            -- '32' | '64' | '64_32' | 'nosize'
    features    BLOB NOT NULL,
    refcount    INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS function_vector (
    binary_id INTEGER NOT NULL, entry_va INTEGER NOT NULL,
    vector_id INTEGER NOT NULL REFERENCES feature_vector(vector_id),
    PRIMARY KEY (binary_id, entry_va)
);
CREATE INDEX IF NOT EXISTS idx_function_vector_vec ON function_vector(vector_id);

-- Corpus feature frequencies -> IDF weights. BSim freezes these at database
-- creation and says the scheme "cannot be changed without reingesting"; making
-- that explicit as a `weights_id` on both the table and the vector row means a
-- reweight is a new weights_id, not a silent corruption of old scores.
CREATE TABLE IF NOT EXISTS feature_weight (
    weights_id   TEXT NOT NULL,
    feature_hash INTEGER NOT NULL,
    doc_count    INTEGER NOT NULL,
    weight       REAL NOT NULL,
    PRIMARY KEY (weights_id, feature_hash)
);

-- Random-hyperplane (SimHash) LSH bands over the weighted vector -- BSim's
-- lsh_k / lsh_L, as rows. BSim ships k=17,L=146 for ~1e7 functions and
-- k=19,L=232 for ~1e8. Candidate generation is L index seeks.
-- Below ~1e5 functions, SKIP THIS TABLE: Ghidra's own embedded H2 backend has
-- no LSH index and scans linearly.
CREATE TABLE IF NOT EXISTS vector_band (
    band_idx  INTEGER NOT NULL,           -- 0 .. L-1
    band_hash INTEGER NOT NULL,           -- k sign bits
    vector_id INTEGER NOT NULL REFERENCES feature_vector(vector_id),
    PRIMARY KEY (band_idx, band_hash, vector_id)
) WITHOUT ROWID;

-- ---------------------------------------------------------------------------
-- 5. JACCARD token sets, for the exact/deterministic lane.
--    `token_ord` is the global order by ASCENDING corpus frequency, so a
--    prefix is the rarest tokens -- that is what makes prefix filtering work.
--
--    MATCH SEMANTICS (AllPairs, exact, deterministic; Mann et al. VLDB 2016
--    find PPJoin+/AdaptJoin "rarely competitive", so stop at AllPairs +
--    length filter and add PPJoin's positional filter only if measured):
--      prefix length for threshold t is  |x| - ceil(t*|x|) + 1
--      length filter is                  t*|x| <= |y| <= |x|/t
--      candidates come from index seeks on the prefix tokens constrained by
--      set_len; every candidate is then VERIFIED by an exact merge, so the
--      result is exact Jaccard with no probabilistic tuning.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS token_dict (
    token_id  INTEGER PRIMARY KEY,
    token     TEXT NOT NULL UNIQUE,
    doc_count INTEGER NOT NULL,
    token_ord INTEGER NOT NULL            -- ascending doc_count
);
CREATE TABLE IF NOT EXISTS function_token (
    fn_key   INTEGER NOT NULL,            -- binary_id<<32 | entry_va, or sigfn_id
    token_id INTEGER NOT NULL,
    pos      INTEGER NOT NULL,            -- rank within the set, for PPJoin positional
    set_len  INTEGER NOT NULL,            -- denormalized so the length filter is a range scan
    PRIMARY KEY (fn_key, token_id)
) WITHOUT ROWID;
-- The inverted index. Only PREFIX tokens need to be here (AllPairs' parsimonious
-- index); the full set lives in function_token for verification.
CREATE TABLE IF NOT EXISTS token_prefix_index (
    token_id INTEGER NOT NULL,
    set_len  INTEGER NOT NULL,
    fn_key   INTEGER NOT NULL,
    pos      INTEGER NOT NULL,
    PRIMARY KEY (token_id, set_len, fn_key)
) WITHOUT ROWID;

-- Approximate lane over the same token sets: b-bit MinHash banded.
-- k hashes -> `sig` BLOB; bands -> index seeks. Determinism requires the k
-- hash seeds be fixed constants recorded here, never a RandomState.
CREATE TABLE IF NOT EXISTS minhash_params (
    params_id TEXT PRIMARY KEY,           -- 'mh-k128-b1-r4-b32'
    k INTEGER NOT NULL, bbits INTEGER NOT NULL,
    n_bands INTEGER NOT NULL, band_rows INTEGER NOT NULL,
    seed INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS function_minhash (
    fn_key    INTEGER NOT NULL,
    params_id TEXT NOT NULL REFERENCES minhash_params(params_id),
    set_len   INTEGER NOT NULL,           -- b-bit correction needs |S|
    sig       BLOB NOT NULL,              -- k*bbits bits; k=128,b=1 -> 16 bytes
    PRIMARY KEY (fn_key, params_id)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS minhash_band (
    params_id TEXT NOT NULL, band_idx INTEGER NOT NULL,
    band_hash INTEGER NOT NULL, fn_key INTEGER NOT NULL,
    PRIMARY KEY (params_id, band_idx, band_hash, fn_key)
) WITHOUT ROWID;

-- ---------------------------------------------------------------------------
-- 6. Byte-level digests. TLSH only; CTPH/ssdeep is retained for FILE level and
--    must not be used at function level (4 KB practical floor, byte-order
--    sensitive -- exactly wrong for reoptimized code).
--    MATCH SEMANTICS: TLSH distance <= 30 (0.0018% FP / 32% detect) or <= 50
--    (0.52% / 65%) per Oliver et al. Distance is not an SQL predicate; the
--    header columns are indexed as a prefilter and the body compared in-process.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS function_tlsh (
    fn_key    INTEGER PRIMARY KEY,
    lvalue    INTEGER NOT NULL,           -- header byte 2, log length
    q1_ratio  INTEGER NOT NULL,
    q2_ratio  INTEGER NOT NULL,
    body      BLOB NOT NULL               -- 32 bytes
);
CREATE INDEX IF NOT EXISTS idx_function_tlsh_hdr
    ON function_tlsh(lvalue, q1_ratio, q2_ratio);

-- ---------------------------------------------------------------------------
-- 7. "Is this function in ANY known library?" gate. One serialized binary-fuse
--    filter per (scheme, arch) over every identity in siglib_function.
--    Query it BEFORE touching the index tables; a negative is definitive.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS identity_filter (
    scheme       TEXT NOT NULL,
    architecture TEXT NOT NULL,
    kind         TEXT NOT NULL,           -- 'binary-fuse-16'
    n_keys       INTEGER NOT NULL,
    built_at     INTEGER NOT NULL,
    filter       BLOB NOT NULL,
    PRIMARY KEY (scheme, architecture)
);

-- ---------------------------------------------------------------------------
-- 8. Match results, so a run is auditable and re-rankable without recompute.
--    `score` and `confidence` are the two BSim numbers; `evidence` records
--    WHICH level resolved it (flirt-L2, warp-constraint, fid-child, ...).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS function_match (
    binary_id  INTEGER NOT NULL, entry_va INTEGER NOT NULL,
    scheme     TEXT NOT NULL,
    sigfn_id   INTEGER REFERENCES siglib_function(sigfn_id),
    score      REAL, confidence REAL,
    rank       INTEGER NOT NULL,
    ambiguous  INTEGER NOT NULL DEFAULT 0,
    evidence   TEXT,
    set_at     INTEGER,
    PRIMARY KEY (binary_id, entry_va, scheme, rank)
);
