import { exit } from 'process';
import { MSVCVector } from './msvc.js'
import HWBP from './hwbp.js'

const baseAddr = Process.enumerateModules()[0].base;
const baseSize = Process.enumerateModules()[0].size;

let procVceBlockEncryptBlowfishCtor: any = null
let currentHashCallType: string
let currentHashCallInput: string

// A terrible global object to keep references to all allocated memory
// this _should_ be cleared once we are done with our allocs, however,
// due to the limited usage of this library, we just allow the memory to
// leak until to the process we are injected into restarts.
let pinned_allocs = new Map();
function customAlloc(size: number): NativePointer {
    let mem = Memory.alloc(size);
    pinned_allocs.set(mem, mem);
    return mem;
}

function customDealloc(ptr: NativePointer): void {
    pinned_allocs.delete(ptr);
}

rpc.exports = {
    installBlowfishLogger: function(): boolean {
        const packageLoadPattern = "55 8B EC 53 57 8B 79 24 85 FF 74 ?? 83 7D 08 00";
        const patternScanResults = Memory.scanSync(baseAddr, baseSize, packageLoadPattern);
        if(patternScanResults.length != 1) {
            console.log("Failed to pattern match for unknown_decryptor::do_decrypt");
            return false;
        }

        const bp = HWBP.attach(patternScanResults[0].address, onCall => {
            let fileDataPtr = onCall.context.sp.add(0x04).readPointer();
            let blowfishKey = onCall.context.sp.add(0x08).readPointer().readAnsiString();
            let fileSize = onCall.context.sp.add(0x0C).readU32();
            let filepath = onCall.context.sp.add(0x10).readPointer().readAnsiString();
            send({message_type:'log', log_type:'bflog', filepath:filepath, file_size:fileSize, blowfish_key:blowfishKey});
        })

        return true;
    },
    installHashLogger: function(): boolean {
        // Find start of function that does CRC32-poly8 checksum of file hashes.
        const hashStringStartPattern = "55 8B EC 8B 55 08 85 D2 75 04 33 C0 5D C3 53";
        const hashStringStartResults = Memory.scanSync(baseAddr, baseSize, hashStringStartPattern);
        if(hashStringStartResults.length != 1) {
            console.log("Failed to pattern match for hash_string(start)");
            return false;
        }
        const hashStringStartAddr = hashStringStartResults[0].address;


        // This is just the final `RET` instruction in the function scanned for above.
        // We scan 12 bytes before, as we are trying to locate the end of the function
        // and can't just pattern scan for `0xC3`.
        const hashStringEndPattern = "42 83 EF 01 75 ?? 5F 5E 8B C1 5B 5D C3";
        const hashStringEndResults = Memory.scanSync(baseAddr, baseSize, hashStringEndPattern);
        if(hashStringEndResults.length != 1) {
            console.log("Failed to pattern match for hash_string(end)");
            return false;
        }
        const hashStringEndAddr = hashStringEndResults[0].address.add(0xC);

        const hashStringBp = HWBP.attach(hashStringStartAddr, onCall => {
            let rawString = onCall.context.sp.add(0x04).readPointer().readAnsiString();
            let usedLength = onCall.context.sp.add(0x08).readU32();

            if (rawString?.length == usedLength) {
                currentHashCallType = "file";
            } else {
                currentHashCallType = "dir";
            }

            currentHashCallInput = rawString?.slice(0, usedLength)!;
        })

        const hashStringEndBp = HWBP.attach(hashStringEndAddr, onCall => {
            const ctx = onCall.context as Ia32CpuContext;
            let hash = ctx.eax;
            send({message_type:'log', log_type:'hashlog', hash_type:currentHashCallType, hash_input:currentHashCallInput, hash_output:hash});
        })

        return true;
    }
}
