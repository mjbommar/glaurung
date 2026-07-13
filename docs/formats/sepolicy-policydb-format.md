# SELinux `policydb` binary format -- implementation spec for the reachability oracle

This is the reverse-engineered, authoritative on-disk layout of the compiled
SELinux kernel policy (`policydb`), captured so the `domain->resource`
reachability query (capability #3, "the load-bearing severity gate") can be
implemented **correct rather than rushed**. Field orders below are taken from
libsepol `src/policydb.c` / `src/avtab.c` (verified against real `secilc`-built
policies at versions 30/33/35). Items marked [OK] are validated end-to-end against
ground truth; [!] need care for real device policy.

The header parser + magic detection are already implemented and tested in
`src/formats/sepolicy/` (`parse_header`, `is_sepolicy`). Everything below is the
next slice.

## Primitives

- All integers little-endian. `u32`, `u16`, `u8` as noted.
- **string**: `u32 len`, then `len` bytes (no NUL).
- **ebitmap**: `u32 mapsize` (always 64), `u32 highbit`, `u32 count`, then
  `count` nodes each `{ u32 startbit; u64 map }`. Empty bitmap = `64,0,0`. [OK]

## Header [OK] (implemented)

`u32 magic (0xf97cff8c)`, `string "SE Linux"`, `u32 version`, `u32 config`
(bit0 = `POLICYDB_CONFIG_MLS`), `u32 sym_num (8)`, `u32 ocon_num`
(version-dependent: 7 at v30, 9 at v33/35). Then:

- ebitmap `policycaps` (v >= 22) [OK]
- ebitmap `permissive_map` (v >= 23) [OK]

## Symbol tables (8, in order) -- then the avtab immediately follows

Each table: `u32 nprim`, `u32 nel`, then `nel` datums via the per-table reader.
Order: `commons(0), classes(1), roles(2), types(3), users(4), bools(5),
sens(6), cats(7)`.

- **common_read**: `u32 len,value,nprim,nel`; string key; `nel`xperm. [OK]
- **perm_read**: `u32 len,value`; string key. [OK]
- **class_read**: `u32 len,len2,value,nprim,nel,ncons`; key; comkey(len2);
  `nel`xperm; **`ncons`xconstraint** [!] (expr trees -- see below; real device
  classes have MLS constraints); `u32 nvalidatetrans` + that many constraints
  [!]; defaults `u32 default_user,default_role,default_range` (v >= 27),
  `u32 default_type` (v >= 28). [OK] for `ncons==0`.
- **role_read**: `u32 len,value,bounds`(bounds v >= 24); key; ebitmap `dominates`;
  ebitmap `types`. [OK]
- **type_read**: `u32 len,value,properties,bounds` (v >= 24); key.
  `properties` flags: `PRIMARY(1)`, `ATTRIBUTE(2)`, `ALIAS(4)`, `PERMISSIVE(8)`.
  [!] **attribute/alias flavors change following reads**; real Android policy has
  thousands of attributes. The type<->attribute membership is the `type_attr_map`
  read *after* the avtab, not inline. [OK] for plain types.
- **user_read**: `u32 len,value,bounds`(v >= 24); key; ebitmap `roles`;
  **if MLS**: `mls_read_range_helper` (`u32 items`; `items`x`u32 sens`;
  ebitmap cat[0]; ebitmap cat[1] if items>1) + `mls_read_level`. [!] (MLS only)
- **bool_read** (`cond_read_bool`): `u32 value,state,len`; key.
- **sens_read**: `u32 len,isalias`; key; `mls_read_level` (`u32 sens`; ebitmap
  cat). Present only when the policy declares sensitivities. [!] (MLS)
- **cat_read**: `u32 len,value,isalias`; key.

## avtab (the allow rules) [OK] -- format validated against ground truth

`avtab_read`: `u32 nel`, then `nel` items.

`avtab_read_item` (v >= 20, `POLICYDB_VERSION_AVTAB`):
`u16 source_type`, `u16 target_type`, `u16 target_class`, `u16 specified`,
then:
- if `specified & AVTAB_XPERMS (0x0700)` (v >= `XPERMS_IOCTL`=30):
  `u8 xperms_specified`, `u8 driver`, `u32 perms[8]`;
- else: `u32 data`.

`specified` values (exactly one bit besides `AVTAB_ENABLED`):
`ALLOWED=0x0001`, `AUDITALLOW=0x0002`, `AUDITDENY=0x0004` (`AVTAB_AV`);
`TRANSITION=0x0010`, `MEMBER=0x0020`, `CHANGE=0x0040` (`AVTAB_TYPE`, `data` = a
type value); xperms `0x0100/0x0200/0x0400`.

`type`/`class` indices are the 1-based `value` fields from the type/class symbol
tables. `data` for an AV rule is the permission bitmap (bit `value-1` per perm).

**Validated** on `sepolicy_nomls.33`:
- `allow untrusted_app(1) foo_device(3):chr_file(1) {ioctl,read}` ->
  `src=1,tgt=3,cls=1,spec=ALLOWED,data=0x3`. [OK]
- `allow system_server(2) bar_device(4):chr_file(1) {ioctl,read,write,open}` ->
  `data=0xF`. [OK]

## The query

```
allows(source_type, target_type, class, perm):
  s = types[source_type].value; t = types[target_type].value
  c = classes[class].value;     bit = 1 << (classes[class].perms[perm].value - 1)
  find avtab entry (s, t, c, ALLOWED); return (entry.data & bit) != 0
```

For full fidelity on real device policy the follow-up must also fold in:
type-attribute expansion (rules written against attributes), conditional-avtab
(booleans), and `allowxperm` for fine-grained `ioctl` command filtering (the
`AVTAB_XPERMS` datum above -- directly relevant to the Linux `.ko` ioctl surface
in `analysis::linux_ioctl`).

## Why this is staged

A reachability oracle that silently mis-parses the symbol tables would return
wrong "can untrusted_app reach X?" verdicts -- worse than no oracle, since every
severity claim is sourced from it. The header/detection slice is landed; this
spec makes the avtab oracle a well-defined, correct implementation rather than a
guess. Real multi-version fixtures (`sepolicy.{30,33,35}` MLS,
`sepolicy_nomls.33`) are available to validate it.
