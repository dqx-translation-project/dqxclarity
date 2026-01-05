// hook for dialogue text
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    56                    - push esi
    8B F1                 - mov esi,ecx
    80 BE EC000000 00     - cmp byte ptr [esi+000000EC],00
    74 07                 - je DQXGame.exe+72B7E6
    C6 86 ED000000 01     - mov byte ptr [esi+000000ED],01
    FF 75 18              - push [ebp+18]
    8B 45 0C              - mov eax,[ebp+0C]
    51                    - push ecx
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

    // cache for translations to avoid blocking on subsequent calls.
    // this provides near instant lookups for previously seen translations.
    const translationCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // in __thiscall, 'this' pointer is in ECX.
                // first stack argument (args[0]) is dialogue_text
                // second stack argument (args[1]) is npc_name
                const textPtr = args[0];
                const npcPtr = args[1];

                if (textPtr.isNull()) {
                    return;
                }

                const originalText = textPtr.readUtf8String();

                if (!originalText || originalText.length === 0) {
                    return;
                }

                // check cache first and return if found.
                if (translationCache.has(originalText)) {
                    const cachedTranslation = translationCache.get(originalText);
                    if (cachedTranslation && cachedTranslation !== originalText) {
                        textPtr.writeUtf8String(cachedTranslation);
                    }
                    return;
                }

                // cache miss - read string and send to python.

                // try to read NPC name (may be null)
                let npcName = "No_NPC";
                if (npcPtr && !npcPtr.isNull()) {
                    try {
                        const npcNameRead = npcPtr.readUtf8String();
                        if (npcNameRead && npcNameRead.length > 0) {
                            npcName = npcNameRead;
                        }
                    } catch (e) {
                        // NPC name read failed, use default
                    }
                }

                send({
                    type: 'get_replacement',
                    text: originalText,
                    npc_name: npcName
                });

                // block thread and wait for python to return.
                var replacement = null;
                var op = recv('replacement', function(message) {
                    replacement = message.text;
                });
                op.wait();

                if (replacement) {
                    // write translation to memory if different
                    if (replacement !== originalText) {
                        textPtr.writeUtf8String(replacement);
                        translationCache.set(originalText, replacement);
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
