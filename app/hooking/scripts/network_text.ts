// hook for network text template string replacements.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    81 EC DC030000        - sub esp,000003DC
    A1 40C5F701           - mov eax,[DQXGame.exe+1C3C540]
    33 C5                 - xor eax,ebp
    89 45 FC              - mov [ebp-04],eax
    8B 45 14              - mov eax,[ebp+14]
    8B 0D C083FA01        - mov ecx,[DQXGame.exe+1C683C0]
    89 45 D8              - mov [ebp-28],eax
    64 A1 2C000000        - mov eax,fs:[0000002C]
    53                    - push ebx
    56                    - push esi
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

    // cache for translations to avoid blocking on repeated text
    const translationCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function (args) {
            // bool __cdecl ProcessTemplateString(int a1, int a2, unsigned int a3, int a4)
            // arg1 is the pointer to the context
            this.arg1 = args[0];
        },

        onLeave: function(retval) {
            try {
                // only process if function returned true
                if (retval.toInt32() !== 1) {
                    return;
                }

                const arg1 = this.arg1;
                if (!arg1 || arg1.isNull()) {
                    return;
                }

                // 0x10 of context - string length
                const stringLength = arg1.add(0x10).readU32();

                // 0x18 of context - address to end of string buffer
                const endOfStringAddr = arg1.add(0x18).readU32();

                // calculate start of string by subtracting length from end address
                const startOfStringAddr = ptr(endOfStringAddr - stringLength);

                // read string content
                if (startOfStringAddr.isNull() || stringLength === 0) {
                    return;
                }

                const originalText = startOfStringAddr.readUtf8String(stringLength);

                // 0x1c of context - pointer to template string
                const templateStringPtr = arg1.add(0x1c).readPointer();
                if (templateStringPtr.isNull()) {
                    return;
                }

                const category = templateStringPtr.readUtf8String();

                if (!originalText || !category) {
                    return;
                }

                // create cache key combining category and text
                const cacheKey = `${category}:${originalText}`;

                // check cache first
                if (translationCache.has(cacheKey)) {
                    const cachedReplacement = translationCache.get(cacheKey);
                    if (cachedReplacement && cachedReplacement !== originalText) {
                        startOfStringAddr.writeUtf8String(cachedReplacement);
                    }
                    return;
                }

                // send to Python for translation/lookup
                send({
                    type: 'get_replacement',
                    text: originalText,
                    category: category
                });

                // block and wait for Python response
                var replacement = null;
                var op = recv('replacement', function(message) {
                    replacement = message.text;
                });
                op.wait();

                if (replacement !== null) {
                    // write replacement to memory if different
                    if (replacement !== originalText) {
                        startOfStringAddr.writeUtf8String(replacement);
                        translationCache.set(cacheKey, replacement);
                    }
                }

            } catch (e) {
                send({
                    type: 'error',
                    payload: `[${hookName}] onLeave error: ${e.message}`
                });
            }
        }
    });
})();
