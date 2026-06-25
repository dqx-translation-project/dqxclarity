// hook for corner text. (8.0: DQXGame.exe+7416D0)
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    83 EC 34              - sub esp,34
    8B 45 14              - mov eax,[ebp+14]
    53                    - push ebx
    56                    - push esi
    8B 75 10              - mov esi,[ebp+10]      ; esi = text (args[2])
    89 4D F4              - mov [ebp-0C],ecx      ; this
    89 45 D8              - mov [ebp-28],eax
    57                    - push edi
    85 F6                 - test esi,esi
    0F84 21040000         - je DQXGame.exe+741B0E

    note: prior to the 8.0 patch this function used a different register
    allocation (text in eax, this in esi). it was recompiled and the old
    signature stopped matching. text pointer is still the 3rd stack arg
    (args[2]).

    top-right corner text from NPCs. seen primarily in v5/v6.
    how it was found:
    - Quest 764 has a way to test reproducing text in the top right
    - Search for the text she says while it's up
      - All strings she might say during the quest are loaded into memory
    - Put a "Find what writes here" on several of the results returned
    - While in the loom portion of the quest, mash any button to fail the
      step and get her to say something new. Hope you picked an address
      that has a temporary string in it and was overwritten with the new
      string.
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

    // Cache for translations to avoid blocking on subsequent calls
    const translationCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // Function signature:
                // unsigned int __thiscall sub_11E7D70(
                //     int this,         // ECX
                //     int a2,           // args[0]
                //     int a3,           // args[1]
                //     const char *a4,   // args[2] - text pointer we need
                //     const char *a5,   // args[3]
                //     ...

                const textPtr = args[2];

                if (textPtr.isNull()) {
                    return;
                }

                const originalText = textPtr.readUtf8String();

                if (!originalText || originalText.length === 0) {
                    return;
                }

                // Check cache first
                if (translationCache.has(originalText)) {
                    const cachedReplacement = translationCache.get(originalText);
                    if (cachedReplacement && cachedReplacement !== originalText) {
                        textPtr.writeUtf8String(cachedReplacement);
                    }
                    return;
                }

                // Send to Python for lookup
                send({
                    type: 'get_replacement',
                    text: originalText
                });

                // Block and wait for Python response
                var replacement = null;
                var op = recv('replacement', function(message) {
                    replacement = message.text;
                });
                op.wait();

                if (replacement) {
                    // Write replacement to memory if different
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
