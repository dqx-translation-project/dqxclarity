LoadImageFromResource(ResourceName) {
    if !(A_IsCompiled) {
        return ResourceName
    }
    else {
        Loop {
            hModule := DllCall("GetModuleHandle", "Ptr", 0, "Ptr")
            Resource := DllCall("FindResource", "Ptr", hModule, "Str", ResourceName, "UInt", RT_RCDATA := 10, "Ptr")
            ResourceSize := DllCall("SizeofResource", "Ptr", hModule, "Ptr", Resource)
            ResourceData := DllCall("LoadResource", "Ptr", hModule, "Ptr", Resource, "Ptr")
            DllCall("Crypt32.dll\CryptBinaryToString", "Ptr", ResourceData, "UInt", ResourceSize, "UInt", 0x01, "Ptr", 0, "UIntP", &B64Len := 0)
            VarSetStrCapacity(&B64, (B64Len << !!1))
            DllCall("Crypt32.dll\CryptBinaryToString", "Ptr", ResourceData, "UInt", ResourceSize, "UInt", 0x01, "Str", B64, "UIntP", B64Len)
            ResourceData := ""
            VarSetStrCapacity(&ResourceData, 0)
            VarSetStrCapacity(&B64, -1)
            B64 := RegExReplace(B64, "\r\n")
            B64Len := StrLen(B64)

            if (!DllCall("Crypt32.dll\CryptStringToBinary", "Str", B64, "UInt", 0, "UInt", 0x01, "Ptr", 0, "UIntP", &DecLen := 0, "Ptr", 0, "Ptr", 0)) {
                return false
            }
            VarSetStrCapacity(&Dec, DecLen)
            if (!DllCall("Crypt32.dll\CryptStringToBinary", "Str", B64, "UInt", 0, "UInt", 0x01, "Str", Dec, "UIntP", &DecLen, "Ptr", 0, "Ptr", 0)) {
                return false
            }

            hData := DllCall("Kernel32.dll\GlobalAlloc", "UInt", 2, "UPtr", DecLen, "UPtr")
            pData := DllCall("Kernel32.dll\GlobalLock", "Ptr", hData, "UPtr")
            DllCall("Kernel32.dll\RtlMoveMemory", "Ptr", pData, "Str", Dec, "UPtr", DecLen)
            DllCall("Kernel32.dll\GlobalUnlock", "Ptr", hData)
            DllCall("Ole32.dll\CreateStreamOnHGlobal", "Ptr", hData, "Int", true, "PtrP", &pStream := 0)
            hGdip := DllCall("Kernel32.dll\LoadLibrary", "Str", "Gdiplus.dll", "UPtr")
            SI := Buffer(16, 0), NumPut("Char", 1, SI)
            DllCall("Gdiplus.dll\GdiplusStartup", "PtrP", &pToken := 0, "Ptr", SI, "Ptr", 0)
            DllCall("Gdiplus.dll\GdipCreateBitmapFromStream", "Ptr", pStream, "PtrP", &pBitmap := 0)
            DllCall("Gdiplus.dll\GdipCreateHBITMAPFromBitmap", "Ptr", pBitmap, "PtrP", &hBitmap := 0, "UInt", 0)
            DllCall("Gdiplus.dll\GdipDisposeImage", "Ptr", pBitmap)
            DllCall("Gdiplus.dll\GdiplusShutdown", "Ptr", pToken)
            DllCall("Kernel32.dll\FreeLibrary", "Ptr", hGdip)
            DllCall(NumGet(NumGet(pStream + 0, 0, "UPtr") + (A_PtrSize * 2), 0, "UPtr"), "Ptr", pStream)
            if (hBitmap != 0) {
                return "HBITMAP:" hBitmap
            }
        }
    }
}
