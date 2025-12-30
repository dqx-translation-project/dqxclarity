// hook for logging hashed filenames.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    8B 55 08              - mov edx,[ebp+08]
    85 D2                 - test edx,edx
    75 04                 - jne DQXGame.exe+1039DE
    33 C0                 - xor eax,eax
    5D                    - pop ebp
    C3                    - ret
    53                    - push ebx
    56                    - push esi
    57                    - push edi
    8B 7D 0C              - mov edi,[ebp+0C]

*/
(function() {
    const hookName = '{{HOOK_NAME}}';
    const signature = '{{SIGNATURE}}';

    const baseAddr = Process.enumerateModules()[0].base;
    const baseSize = Process.enumerateModules()[0].size;

    const results = Memory.scanSync(baseAddr, baseSize, signature);
    if (results.length != 1) {
        send({
            type: 'error',
            payload: `[${hookName}] Function not found with signature`
        });
        return;
    }

    const funcAddress = results[0].address;
    send({
        type: 'info',
        payload: `[${hookName}] Found at: ${funcAddress}`
    });

    // important for this function to be executed onLeave as the return value
    // has the checksum value. we read the stack remnants to figure out what
    // was calculated against.
    Interceptor.attach(funcAddress, {
        onLeave: function(retval) {
            try {
                const edi = this.context.edi;
                const esp = this.context.esp;

                const dataType = edi.toUInt32();

                let hashType;
                let hashInput;

                if (dataType === 0xFFFFFFFF) {
                    hashType = "dir";

                    const pathSize = esp.add(0x18).readU32()
                    const filepathPtr = esp.add(0x14).readPointer();

                    hashInput = filepathPtr.readUtf8String(pathSize);
                } else {
                    hashType = "file";

                    const filepathPtr = esp.add(0x30).readPointer();

                    hashInput = filepathPtr.readUtf8String();
                }

                const hashOutput = '0x' + retval.toUInt32().toString(16);

                send({ type: 'info', payload: `[DEBUG] ${hashType},${hashInput},${hashOutput}`})

                // send logging request to python for async logging.
                send({
                    type: 'hash_data',
                    hash_type: hashType,
                    hash_input: hashInput,
                    hash_output: hashOutput
                });

            } catch (e) {
                send({
                    type: 'error',
                    payload: `[${hookName}] onLeave error: ${e.message}`
                });
            }
        }
    });
})();
