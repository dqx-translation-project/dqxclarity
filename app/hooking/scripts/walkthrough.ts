// hook for walkthrough text replacements.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    83 EC 40              - sub esp,40
    8B 15 90C2F901        - mov edx,[DQXGame.exe+1C5C290]
    53                    - push ebx
    8B D9                 - mov ebx,ecx
    89 5D FC              - mov [ebp-04],ebx
    56                    - push esi
    57                    - push edi
    85 D2                 - test edx,edx
    ...
    ...
 >> E8 437FFFFF           - call DQXGame.exe+2D59E0
 >> 8D B8 EC000000        - lea edi,[eax+000000EC]
    8B CF                 - mov ecx,edi
    8D 51 01              - lea edx,[ecx+01]
    8A 01                 - mov al,[ecx]
    41                    - inc ecx
    84 C0                 - test al,al
    75 F9                 - jne DQXGame.exe+2DDAA8
    2B CA                 - sub ecx,edx

    to find this, search for walkthrough text:
    メインコマンド『せんれき』の
    ^ is text when you are caught up with the story.
    you are looking for the original source string that is read,
    not the ones that are just written to the screen. to figure
    this out, with the command window closed, update the first
    jp letter with "eee", then open the window. if the window
    shows "eee", then put a "what reads this" breakpoint here.
    should be the entry, "mov al, [ecx]". it should only trigger
    when the command window opens, that's it. from there, go down
    a few instructions and look for a clean place to hook.
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

    // subtract 0x38 to get to function prologue
    const funcAddress = results[0].address.sub(0x38);

    // verify we're at a valid function prologue (55 8B EC = push ebp; mov ebp, esp)
    const prologueBytes = funcAddress.readByteArray(3);
    if (prologueBytes === null) {
        send({
            type: 'error',
            payload: `[${hookName}] Failed to read function prologue`
        });
        return;
    }

    const bytes = new Uint8Array(prologueBytes);
    if (bytes[0] !== 0x55 || bytes[1] !== 0x8B || bytes[2] !== 0xEC) {
        send({
            type: 'error',
            payload: `[${hookName}] Invalid prologue at ${funcAddress}: expected 55 8B EC, got ${bytes[0].toString(16)} ${bytes[1].toString(16)} ${bytes[2].toString(16)}`
        });
        return;
    }

    send({
        type: 'info',
        payload: `[${hookName}] Found at: ${funcAddress} (verified prologue)`
    });

    // cache for translations to avoid blocking
    const translationCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // int __thiscall sub_DADA60(_DWORD *this, int a2)
                // this = ECX (implicit), a2 = args[0]

                const esp = this.context.esp;
                const textPtrAddress = esp.add(8).readPointer();

                if (textPtrAddress.isNull()) {
                    return;
                }

                const textAddress = textPtrAddress.add(236);
                const originalText = textAddress.readUtf8String();

                if (!originalText || originalText.length === 0) {
                    return;
                }

                // check cache first
                if (translationCache.has(originalText)) {
                    const cachedReplacement = translationCache.get(originalText);
                    if (cachedReplacement && cachedReplacement !== originalText) {
                        textAddress.writeUtf8String(cachedReplacement);
                    }
                    return;
                }

                // send to Python for translation/lookup
                send({
                    type: 'get_replacement',
                    text: originalText
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
                        textAddress.writeUtf8String(replacement);
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
