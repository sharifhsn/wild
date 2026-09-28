# Compact artifact payload cache

Wild reads compact Rust object payloads from independently compressed blocks.
By default, each decoded block stays in memory until the link finishes. This is
fast and keeps the existing borrowed-section API, but total decoded payload can
grow with the link.

On Unix, set `WILD_COMPACT_CACHE_BYTES` to enable a bounded resident-page mode,
for example:

```sh
WILD_COMPACT_CACHE_BYTES=268435456 wild ...
```

The value is a byte limit for the LRU working set of decoded blocks. The reader
streams each requested block into a temporary file and maps it read-only. When
the tracked set exceeds the limit, it advises the OS to drop old mapped pages.
Borrowed section slices keep their virtual addresses; a later read faults the
bytes back from the temporary file. This avoids whole-object extraction and
keeps the direct compact-object linker path.

This mode is optional because it trades memory for temporary I/O and scratch
space. The temporary backing can approach the total decoded payload of selected
objects, and pages that were dropped may need to be read again. The byte limit
covers the cache's logical resident window. It does not cap eager ELF/symbol
metadata, active section reads, process RSS, or operating-system page cache.
Unset the variable to retain the pinned in-memory cache.
