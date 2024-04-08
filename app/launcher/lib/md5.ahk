MD5_File(Path, &md5 := "") {
    ctx := Buffer(104, 0)
    buf := FileRead(Path, "RAW")
    DllCall("advapi32\MD5Init", "Ptr", ctx)
    DllCall("advapi32\MD5Update", "Ptr", ctx, "Ptr", buf, "UInt", buf.Size)
    DllCall("advapi32\MD5Final", "Ptr", ctx)
    loop 16
        md5 .= Format("{:02x}", NumGet(ctx, 87 + A_Index, "UChar"))
    return md5
}
