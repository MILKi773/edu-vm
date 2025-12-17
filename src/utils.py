def mask(n: int) -> int:
    return (1 << n) - 1

def pack_fields(pairs):
    val = 0
    for (v, start, width) in pairs:
        val |= (v & mask(width)) << start
    return val  # Return full integer, no 32-bit limit

def unpack_field(cmd: int, start: int, width: int) -> int:
    return (cmd >> start) & mask(width)

