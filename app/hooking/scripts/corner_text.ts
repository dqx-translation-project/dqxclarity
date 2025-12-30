// hook for corner text.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    8B 45 10              - mov eax,[ebp+10]
    83 EC 14              - sub esp,14
    53                    - push ebx
    8B 5D 14              - mov ebx,[ebp+14]
    56                    - push esi
    8B F1                 - mov esi,ecx
    57                    - push edi
    85 C0                 - test eax,eax
    0F84 16020000         - je DQXGame.exe+717F9F

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
                    // Cache the result
                    translationCache.set(originalText, replacement);

                    // Write replacement to memory if different
                    if (replacement !== originalText) {
                        textPtr.writeUtf8String(replacement);
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
