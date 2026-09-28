// Compressing debug sections recomputes the file offsets of the sections after them. The first
// writable segment starts with `.tdata`, whose alignment is smaller than the segment's (raised
// here by the aligned `.tbss` variable), so its file offset needs padding to stay congruent with
// its address. Recomputing that offset from the section alignment alone dropped the padding,
// shifting the segment's file contents: TLS initializers, `.dynamic` and data were read from the
// wrong place at run time.

//#AbstractConfig:default
//#LinkerDriver:gcc
//#CompArgs:-g
//#SkipArch:ppc64le
//#DiffIgnore:section.debug_*
//#DiffIgnore:section.rodata
//#DiffIgnore:section.data

//#Config:zlib:default
//#LinkArgs:-Wl,--compress-debug-sections=zlib

//#Config:zstd:default
//#RequiresLinkerFlags:--compress-debug-sections=zstd
//#RequiresZstdCompression:true
//#LinkArgs:-Wl,--compress-debug-sections=zstd

static __thread volatile long tls_initialized = 0x1122334455667788;
static __thread volatile _Alignas(64) unsigned char tls_zeroed[3];
static volatile long data_value = 40;

int main(void) {
  if (tls_initialized != 0x1122334455667788) {
    return 2;
  }
  if (tls_zeroed[0] != 0 || tls_zeroed[2] != 0) {
    return 3;
  }
  return (int)data_value + 2;
}
