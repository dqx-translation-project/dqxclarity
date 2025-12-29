// hook for logging blowfish decryption keys.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    53                    - push ebx
    57                    - push edi
    8B 79 24              - mov edi,[ecx+24]
    85 FF                 - test edi,edi
    74 59                 - je DQXGame.exe+104265
    83 7D 08 00           - cmp dword ptr [ebp+08],00
    74 53                 - je DQXGame.exe+104265
    8B 45 0C              - mov eax,[ebp+0C]

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

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // bool __thiscall sub_BD4200(
                //     unsigned __int8 (__cdecl **this)(int, const char *, int),  // ECX
                //     int a2,              // args[0]
                //     const char *a3,      // args[1] - blowfish_key
                //     int a4,              // args[2] - total_size
                //     int a5)              // args[3] - filename

                const blowfishKeyPtr = args[1];
                const totalSize = args[2].toInt32();
                const filenamePtr = args[3];

                const blowfishKey = blowfishKeyPtr.readUtf8String() || "";
                const filename = filenamePtr.readUtf8String() || "";

                // send to python for async logging.
                send({
                    type: 'blowfish_data',
                    filename: filename,
                    file_size: totalSize,
                    blowfish_key: blowfishKey
                });

            } catch (e) {
                send({
                    type: 'error',
                    payload: `[${hookName}] onEnter error: ${e.message}`
                });
            }
        }
    });
})();
