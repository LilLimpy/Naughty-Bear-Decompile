Note: This 'documentation' was generated and provided by Claude Sonnet 4.6 / AI while studying .lu files contained within the Naughty Bear PS3 files. Documenting an almost 2 decade old closed source custom format is unfortunately beyond me. I generally checked the contents of the doc to make sure it wasn't entirely gibberish, though expect mistakes nonetheless. Further edits will be made as better information is uncovered.

# Naughty Bear (PS3) `.lu` Container Format — Reverse Engineering Notes

**Source files analyzed:** `beartrap.lu` (258,280 bytes), `beartrap_vram.lu` (187,352 bytes)
**Method:** Byte-level structural analysis, cross-validated programmatically (offsets/sizes checksum exactly against both files' total byte counts — not guesswork).
**Confidence key:** ✅ Confirmed/validated · 🟡 Strong hypothesis · ❓ Open question

---

## 1. Big-picture structure

Both files share **one container shell**:

```
[ Header ]  →  [ Resource Table: N × 24-byte records ]  →  [ Data Blob ]
```

- The **Resource Table** immediately follows the header.
- The **Data Blob** immediately follows the table and is fully, exactly accounted for by the table's `size`/`dataOffset` fields — i.e. `header_size + table_size + sum(aligned sizes) == file_size` with **zero slack bytes**, verified on both files. This is the load-bearing fact that makes the rest of this doc possible: once you know the table layout, the rest of the file is self-describing.
- `beartrap.lu` is the "main"/CPU-resident file: behavior scripts + small metadata. `beartrap_vram.lu` is a companion "leaf" file holding GPU-bound geometry, referenced by name from the main file's header. All multi-byte integers observed so far are **big-endian** (unusual for x86 tooling, but expected for PS3/Cell, which is big-endian).

---

## 2. Header (bytes `0x00`–`0x80` in `beartrap.lu`, `0x00`–`0x50` in `beartrap_vram.lu`)

```
000000: 01 70 73 33 04 10 00 00 27 66 86 f2 00 00 00 06   .ps3....'f......
000010: 00 00 00 04 00 00 00 2d 2d 0a 49 54 43 52 41 50   .......--.ITCRAP
000020: ff ff ff ff ff ff ff ff 00 00 00 00 00 00 00 28   ...............(
000030: 00 00 00 11 00 00 00 3c 00 00 00 54 00 00 00 00   .......<...T....
000040: 00 00 0c 78 00 00 00 00 62 65 61 72 74 72 61 70   ...x....beartrap
000050: 5f 76 72 61 6d 2e 6c 75 00 bf bf bf 00 00 00 00   _vram.lu........
000060: 00 03 e4 50 00 00 00 00 00 00 00 01 ff ff ff ff   ...P............
000070: 00 00 00 00 00 00 00 60 00 00 00 81 bf bf bf bf   .......`........
```

| Offset | Bytes | Value | Notes |
|---|---|---|---|
| `0x00` | `01 70 73 33` | — | ✅ Magic: `0x01` + ASCII `"ps3"`. Platform/format tag. Worth checking whether mobile `.lu`-equivalent assets use a different 1st byte. |
| `0x04` | `04 10 00 00` | — | ❓ Unknown flags/version word. |
| `0x08` | `27 66 86 f2` | — | ✅ **Identical in both `beartrap.lu` and `beartrap_vram.lu`.** Almost certainly a CRC32 (matches the lowercase-CRC32 hash convention already confirmed in earlier sessions) of the shared base resource name `"beartrap"` — i.e. a bundle ID common to every file belonging to one game object. |
| `0x0C` | `00 00 00 06` | 6 | ❓ Some kind of count (6 of something). |
| `0x10` | `00 00 00 04` | 4 | ❓ Some kind of count (4 of something). |
| `0x17` | `2d 2d 0a 49 54 43 52 41 50` | `"--\nITCRAP"` | ❓ Literal ASCII tag, identical in both files. The leading `"--\n"` looks like a Lua single-line comment opener, but a single-line comment can't safely wrap binary data containing `0x0A` bytes, so this is more likely just a fixed 9-byte tool/format signature (possibly a joke/internal tool name) than an actual Lua trick. Flag for cross-checking against other `.lu` files — if it's truly constant, it's a second magic/version marker. |
| `0x28` | `ff ff ff ff ff ff ff ff` | — | Sentinel block (same `0xFFFFFFFF` sentinel reused in resource-table records, see §3). |
| `0x30`–`0x3C` | `28, 11, 3c, 54` (BE u32 each) | 40, 17, 60, 84 | ❓ Small integers — candidates: counts/byte-offsets describing some sub-section of the header itself. Not yet tied to anything concrete. |
| `0x44` | `00 00 0c 78` | 3192 | ❓ Close to, but **not equal to**, the resource-table size (3224 bytes, see §3) — off by exactly 32 bytes. Possibly a "table size minus trailer" or computed from a slightly different base. Needs checking against a `.lu` file with a different record count. |
| `0x4C` | `"beartrap_vram.lu\0"` | — | ✅ **Companion-file name.** This is how the main file references its VRAM-resident counterpart. `beartrap_vram.lu` has no equivalent string (it's the leaf — nothing points further down). |
| right after | `bf bf bf bf` (×1 or more) | — | ✅ Recurring **padding/filler constant `0xBF`**, distinct from the `0xFF` sentinel. Appears in several header gaps in both files — likely just an "unused byte" fill pattern from the original packer, not meaningful data. |
| `0x60` | `00 03 e4 50` | 254,544 | ❓ A large size-like value. **Doesn't exactly match** any of the precisely-confirmed totals (table+blob = 255,056 bytes in `beartrap.lu`); off by 512. Possibly a size field from an earlier "uncompressed/unpadded" computation, or refers to something not yet identified. Worth comparing against other objects' `.lu` files to see if the discrepancy is a constant offset. |
| `0x6C` | `00 00 00 01` | 1 | ❓ Possibly "version" or "1 companion file" count. |
| `0x70` | `ff ff ff ff` | — | Sentinel again. |
| `0x78` | `00 00 00 60` | 96 | ❓ |
| `0x7C` | `00 00 00 81` | 129 | ✅ **Exactly matches the resource-table record count (129) in `beartrap.lu`!** This is the one header field with a clean, exact match — **use this as the authoritative record count** rather than scanning for the `0xFFFFFFFF` sentinel break (which works but is a hack). |

`beartrap_vram.lu`'s header is shorter (ends around `0x50` instead of `0x80`) and skips the companion-filename block entirely, consistent with it being the "no further dependencies" leaf file. Its corresponding record-count field should be checked the same way (expect a header field equal to 27).

---

## 3. Resource Table — the core of the format

Immediately after the header is a flat array of **fixed 24-byte records**, one per resource. Table length = header field at `0x7C` (record count) × 24 bytes. Table ends exactly where the Data Blob begins.

```c
struct LuRecord {            // 24 bytes, all fields big-endian
    uint32_t hash;            // 0x00  CRC32(?) of a resource/script identifier
    uint32_t type;             // 0x04  packed type/category + subtype/format bits
    uint32_t sentinel;         // 0x08  ALWAYS 0xFFFFFFFF in every record observed (129+27 records, zero exceptions)
    uint32_t size;             // 0x0C  byte length of this resource's data in the blob
    uint32_t dataOffset;       // 0x10  byte offset into the blob, RELATIVE TO END OF TABLE — not file start!
    uint32_t format;           // 0x14  near-constant "format/flags" tag, shared within a resource category
};
```

### 3.1 `dataOffset` semantics — ✅ fully confirmed

- `dataOffset` is **relative to the first byte after the last table record**, not relative to file start.
- Successive records' data is **packed contiguously**, then **padded up to the next 16-byte boundary** before the next record's data starts. (Verified record-by-record across both files: `next.dataOffset == round_up_16(prev.dataOffset + prev.size)`, with zero exceptions.)
- The **last** record's `dataOffset + size`, rounded up to 16, equals exactly `file_size − table_end`. Verified exactly on both files:
  - `beartrap.lu`: table ends at `0xC98` (3224); last record ends at byte 255,056; `3224 + 255056 = 258280` = file size. ✅
  - `beartrap_vram.lu`: table ends at `0x2D8` (728); last record ends at byte 186,624; `728 + 186624 = 187352` = file size. ✅

### 3.2 `sentinel` field

Always `0xFFFFFFFF` — useful as a structural validity check when scanning for the table's start/end, but its actual *meaning* (if any — could be a vestigial "parent index: none" or "next: none" field from a more general linked structure) is ❓ unknown.

### 3.3 `hash` field

🟡 Almost certainly CRC32 (matches the lowercase-CRC32 convention already confirmed for this project). For the 16 script-type records in `beartrap.lu` we now have ground truth: each record's `hash` pairs with a known plaintext path string (see §4.2) — **this is your test set** for confirming the exact CRC32 variant (poly, init, reflect, lowercase-vs-original-case input, full path vs. filename-only, with/without the `z:\devilsnightdata\...` prefix, etc.).

### 3.4 `type` and `format` fields — taxonomy (from `beartrap.lu`, 129 records)

Grouping every record by `(type, format)`:

| type | format | count | size range | likely category |
|---|---|---|---|---|
| `0x04300012` | `0x04f000ef` | 1 | 420 | ❓ unique, first record |
| `0x0430000e` | `0x04f000ef` | 1 | 1266 | ❓ unique, second record |
| `0x04300009` | `0x04f000ef` | 7 | 72–312 | ❓ small uniform group |
| `0x04300003` | `0x04f000ef` | 11 | 108–268 | ❓ small uniform group |
| `0x04300000` | `0x04f000ef` | 11 | 320–6096 | ❓ medium group |
| `0x00000102` | `0x04f000ef` | 1 | 2115 | ❓ one-off, distinct type pattern |
| `0x04000001` | `0x04f000ef` | 1 | 1900 | ❓ one-off |
| `0x04000007` | `0x07f000ef` | 1 | **71080** | ❓ by far the largest non-script entry — strong texture-atlas or big-buffer candidate |
| `0x24200007` | `0x07f000ef` | 14 | 104–136 | ❓ tight, small, uniform — metadata-sized |
| `0x04800018` | `0x04f000ef` | 3 | 3012–3124 | ❓ |
| `0x04c00000` | `0x04f000ef` | 9 | 224–584 | 🟡 part of a 62-record interleaved cluster, idx 51–112 (see below) |
| `0x04c0000f` | `0x04f000ef` | 22 | 144 (constant!) | 🟡 same cluster — fixed-size, looks like a per-item header/transform block |
| `0x04c00008` | **`0x04f004ef`** | 6 | 208–**17080** | 🟡 same cluster, but the `format` differs in one nibble from its siblings, and sizes balloon up to 17 KB — best texture-or-big-resource candidate inside the cluster |
| `0x04c00010` | `0x04f000ef` | 21 | 188–988 | 🟡 same cluster |
| `0x04c0000a` | `0x04f000ef` | 4 | 80–112 | 🟡 same cluster |
| `0x04b00000` | `0x04f000ef` | **16** | 223–7936 | ✅ **Embedded Lua 5.1 scripts** — fully decoded, see §4 |

The five `0x04c0000X` sub-types (62 records, indices 51–112 contiguous) are clearly one **interleaved per-part cluster** — most likely one repeated metadata block per moving sub-part of the trap (jaw L, jaw R, spring, chain links, anchor stake, teeth, etc. — a bear trap has a lot of small articulated pieces). The `0x04c0000f` entries being a *constant* 144 bytes every time strongly suggests a fixed-layout struct (transform matrix? bounding volume? attachment point?) repeated once per part — a good next target for a single-file "guess the struct" pass, since fixed size + repetition is the easiest pattern to brute-force against in-game behavior (e.g. compare against the `beartrap_*.lua` scripts' part names/pivots).

---

## 4. The embedded Lua 5.1 script subsystem (✅ fully decoded)

`beartrap.lu`'s 16 records of `type = 0x04B00000` are **complete, self-contained Lua 5.1 bytecode chunks** — this is a genuinely solid result and the headline finding of this pass.

### 4.1 Per-record internal layout

Each `0x04B00000` record's blob (`data[abs_offset : abs_offset+size]`) decomposes as:

```
[ small offset mini-table, ~28–32 bytes, purpose ❓ unconfirmed — looks like ascending u32 BE offsets ]
[ u32 BE: length of path string that follows            ]
[ null-terminated absolute dev path, e.g. "z:\devilsnightdata\assets\...\foo.lua\0" ]
[ standard Lua 5.1 bytecode dump, starting at signature 1B 4C 75 61 ('\x1bLua') ]
```

The record's declared `size` covers the **entire** blob above (header-table + path + full bytecode) — confirmed by checking that record *N*'s data ends exactly where record *N+1*'s data begins, for all 16 scripts, with no remainder/gap to explain. So **you can extract each full compiled script in one slice**, no need to hand-parse Lua bytecode structure to find its end.

### 4.2 All 16 scripts found (in file order)

| hash | size (bytes) | bytecode len | path (relative to `z:\devilsnightdata\`) |
|---|---|---|---|
| `a8adabec` | 223 | 131 | `assets\scripts\global\object.lua` |
| `92243fcd` | 7463 | 7351 | `assets\3d\objects\weapons\scripts\weaponmethods.lua` |
| `81e1fcb3` | 5132 | 5012 | `assets\3d\objects\weapons\scripts\pickupsmallhandobject.lua` |
| `370420cb` | 5199 | 5055 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_receivestealthkillhelpescape.lua` |
| `abc8040f` | 3591 | 3459 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_dostealthkill.lua` |
| `88404d7c` | 3494 | 3354 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_dostealthkillhelpescape.lua` |
| `011e9a4f` | 6065 | 5929 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_receivestealthkill.lua` |
| `95b19108` | 5328 | 5204 | `assets\3d\objects\weapons\beartrap\scripts\stuckinbeartrap.lua` |
| `64e13541` | 5568 | 5444 | `assets\3d\objects\weapons\beartrap\scripts\escapebeartrap.lua` |
| `3dafdaf6` | 5774 | 5646 | `assets\3d\objects\weapons\beartrap\scripts\helpescapebeartrap.lua` |
| `02f7d308` | 4658 | 4538 | `assets\3d\objects\weapons\beartrap\scripts\setbeartrap.lua` |
| `17b2547f` | 6380 | 6244 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_receivescareattack.lua` |
| `bd64ca3f` | 3989 | 3857 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_doscareattack.lua` |
| `d61e211e` | 4932 | 4788 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_receivescareattackhelpescape.lua` |
| `695a4ca9` | 3917 | 3777 | `assets\3d\objects\weapons\beartrap\scripts\beartrap_doscareattackhelpescape.lua` |
| `f209aae1` | 7936 | 7812 | `assets\3d\objects\weapons\beartrap\scripts\beartraptrigger.lua` |

This maps the full bear-trap behavior state machine: set → trigger → stealth-kill (do/receive, ± help-escape variant) → scare-attack (do/receive, ± help-escape variant) → stuck-in/escape/help-escape.

**Bonus find:** every path embeds the original build's dev-drive layout, confirming the PS3 build's internal codename was **`devilsnightdata`** ("Devil's Night"), with source tree `assets\scripts\global\`, `assets\3d\objects\weapons\`, and `assets\3d\objects\weapons\<objectname>\scripts\` for object-specific behavior. Worth grepping other extracted `.lu` files for this same path prefix to map out the whole original source tree.

### 4.3 Lua bytecode header — partial match to spec

The bytecode signature found is `1B 4C 75 61 51 00 01 04 04 04 08 08`, i.e.:

| byte | value | standard Lua 5.1 meaning | matches? |
|---|---|---|---|
| 0–3 | `1B 4C 75 61` | signature `ESC L u a` | ✅ |
| 4 | `51` | version = 5.1 | ✅ |
| 5 | `00` | format = official | ✅ |
| 6 | `01` | endianness = little | ✅ (bytecode itself is **little-endian**, even though the container header above is big-endian — don't mix these up) |
| 7 | `04` | sizeof(int) = 4 | ✅ |
| 8 | `04` | sizeof(size_t) = 4 | ✅ |
| 9 | `04` | sizeof(Instruction) = 4 | ✅ |
| 10 | `08` | sizeof(lua_Number) = 8 (double) | ✅ |
| 11 | `08` | expected: "lua_Number is integral" flag (0 or 1) | ❓ **doesn't fit** — got `0x08`, not `0`/`1` |

Eleven of twelve header bytes match stock Lua 5.1 exactly. The last byte mismatch could mean: (a) the PS3 SDK's Lua fork reorders/adds a field here, or (b) byte 11 is already the start of the actual chunk body and the "integral" flag is genuinely just not present in this build.

---

## 5. `beartrap_vram.lu` — geometry data, and a likely answer to the LOD/sub-buffer question

27 records, table at `0x50`–`0x2D8`. Only two distinct `type` values appear, both with the same `format = 0x07f00cef` (uniform across the whole file — makes sense, since a single file dedicated to one GPU resource kind doesn't need much format variety):

- **`type = 0x0420002F`** — 12 records, sizes: `43776 ×3, 256, 384 ×7, 2816 ×2, 11008`
- **`type = 0x04200030`** — 15 records, sizes: `640 ×2, 6912 ×2, 1408, 18432, 128 ×8`
- One special `hash=0, type=00000001, size=0` record at index 0 — size 0, doesn't consume any blob space; almost certainly a non-resource header/count record rather than real data. ❓

### 5.1 Strong evidence `0x2F` = vertex buffers, `0x30` = index buffers

- All `0x2F` sizes are evenly divisible by **36** *or* by smaller factors consistent with fewer per-vertex attributes — and the three identical **43,776-byte** entries divide out to **exactly 1216.0 vertices** at the already-confirmed 36-byte interleaved POS/NRM/UV stride. ✅ This strongly reconfirms the stride-36 vertex format on a second, independent mesh.
- All `0x30` sizes divide evenly by 2 (consistent with `uint16` index buffers) and several repeat in **identical pairs** (two 128-byte entries appear three separate times; two ~640/6912-byte pairs appear at the start).

### 5.2 The repeating triplet pattern — likely the LOD/sub-buffer answer

The back half of the table (indices 18–26) repeats a clean **3-record group**, three times in a row:

```
[ idx 18,19] type 0x30, size 128, size 128      (two index buffers)
[ idx 20   ] type 0x2F, size 2816                (one vertex buffer)
---
[ idx 21,22] type 0x30, size 128, size 128
[ idx 23   ] type 0x2F, size 11008
---
[ idx 24,25] type 0x30, size 128, size 128
[ idx 26   ] type 0x2F, size 2816
```
