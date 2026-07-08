idf_component_register(
    SRCS "opendroneid.c"
    INCLUDE_DIRS "include"
)

# We only note the presence of an Authentication message, never decode all its
# pages. Shrinking ODID_AUTH_MAX_PAGES from the default 16 to 1 cuts the size of
# ODID_UAS_Data by ~480 bytes so the decode scratch fits comfortably on the
# NimBLE host task stack. PUBLIC so every consumer of the header (drone_rid.c)
# sees the same struct layout — a mismatch here would be an ABI bug.
target_compile_definitions(${COMPONENT_LIB} PUBLIC ODID_AUTH_MAX_PAGES=1)
