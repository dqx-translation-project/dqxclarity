// hook for entity nameplates.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    56                    - push esi
    8B B1 88010000        - mov esi,[ecx+00000188]
    85 F6                 - test esi,esi
    74 16                 - je DQXGame.exe+141B54
    8B 45 08              - mov eax,[ebp+08]
    8D 4E 08              - lea ecx,[esi+08]
    51                    - push ecx
    8B D4                 - mov edx,esp
    89 02                 - mov [edx],eax
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

    // cache for translations to avoid blocking
    const translationCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // int __thiscall UpdateEntityNameplate(
                //     _DWORD *this,  // ECX
                //     int a2,        // args[0] - name pointer
                //     int a3)        // args[1]

                const namePtr = args[0];

                if (namePtr.isNull()) {
                    return;
                }

                const originalName = namePtr.readUtf8String();

                if (!originalName || originalName.length === 0) {
                    return;
                }

                // check cache first
                if (translationCache.has(originalName)) {
                    const cachedReplacement = translationCache.get(originalName);
                    if (cachedReplacement && cachedReplacement !== originalName) {
                        namePtr.writeUtf8String(cachedReplacement);
                    }
                    return;
                }

                // get replacement from python.
                send({
                    type: 'get_replacement',
                    name: originalName
                });

                // block and wait for python response.
                var replacement = null;
                var op = recv('replacement', function(message) {
                    replacement = message.name;
                });
                op.wait();

                if (replacement) {
                    // cache the result
                    translationCache.set(originalName, replacement);

                    // write replacement to memory if different
                    if (replacement !== originalName) {
                        namePtr.writeUtf8String(replacement);
                    }
                }

            } catch (e) {
                send({
                    type: 'error',
                    payload: `[${hookName}] onEnter error: ${e.message}`
                });
            }
        }
    });
})();
