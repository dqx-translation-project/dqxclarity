// hook for translating a quest.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    53                    - push ebx
    8B 5D 08              - mov ebx,[ebp+08]
    56                    - push esi
    8B F1                 - mov esi,ecx
    57                    - push edi
    8B 03                 - mov eax,[ebx]
    BF 38000000           - mov edi,00000038
    89 06                 - mov [esi],eax
    ...
    ...
    88 86 57030000        - mov [esi+00000357],al
    5E                    - pop esi
    5B                    - pop ebx
    5D                    - pop ebp
    C2 0400               - ret 0004

    - talk to some purple npc that has a quest
    - when the quest comes up, copy some text from it
    - search for it
    - find what accesses it
    this covers accepting a quest and quests from the map.
    might change between patches unfortunately.
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

    // our initial result is at the bottom of the function, but we want to hook
    // at the prologue. not sure if this will need adjusting throughout patches,
    // but result - 0x115 will give us function start.
    const funcAddress = results[0].address.sub(0x115);

    // verify the function prologue before hooking. need to make sure that
    // when we go backwards, we're hooking the top of the function and not
    // something else.
    const prologueBytes = funcAddress.readByteArray(3);
    const expectedPrologue = [0x55, 0x8b, 0xec]; // push ebp, mov ebp, esp

    if (prologueBytes === null) {
        send({
            type: 'error',
            payload: `[${hookName}] Failed to read function prologue (check offset to prologue)`
        });
        return;
    }

    const actualBytes = new Uint8Array(prologueBytes);
    if (actualBytes[0] !== expectedPrologue[0] ||
        actualBytes[1] !== expectedPrologue[1] ||
        actualBytes[2] !== expectedPrologue[2]) {
        send({
            type: 'error',
            payload: `[${hookName}] Prologue mismatch. Expected: 55 8b ec, Got: ${Array.from(actualBytes).map(b => b.toString(16).padStart(2, '0')).join(' ')}`
        });
        return;
    }

    send({
        type: 'info',
        payload: `[${hookName}] Found at: ${funcAddress} (verified prologue)`
    });

    // cache for quest translations to avoid blocking on subsequent calls.
    // this provides near instant lookups for previously seen quests.
    // - key: quest description (unique identifier for quest)
    // - value: object with all 5 field replacements
    const questCache = new Map();

    Interceptor.attach(funcAddress, {
        onEnter: function(args) {
            try {
                // int __thiscall CopyQuestData(_DWORD *this, int a2)
                // 'this' pointer is in ECX register
                // args[0] is the first stack argument
                const baseAddr = args[0];

                if (baseAddr.isNull()) {
                    return;
                }

                // read quest description first to check cache.
                const questDesc = baseAddr.add(132).readUtf8String() || "";

                // quick check: if quest description is empty, return.
                if (!questDesc || questDesc.length === 0) {
                    return;
                }

                // check cache for translations first. doesn't block thread this way.
                if (questCache.has(questDesc)) {
                    const replacements = questCache.get(questDesc);

                    if (replacements) {
                        if (replacements.subquestName) {
                            baseAddr.add(20).writeUtf8String(replacements.subquestName);
                        }
                        if (replacements.questName) {
                            baseAddr.add(76).writeUtf8String(replacements.questName);
                        }
                        if (replacements.questDesc) {
                            baseAddr.add(132).writeUtf8String(replacements.questDesc);
                        }
                        if (replacements.questRewards) {
                            baseAddr.add(640).writeUtf8String(replacements.questRewards);
                        }
                        if (replacements.questRepeatRewards) {
                            baseAddr.add(744).writeUtf8String(replacements.questRepeatRewards);
                        }
                    }
                    return;
                }

                // cache miss - read all quest strings and send to python.
                const subquestName = baseAddr.add(20).readUtf8String() || "";
                const questName = baseAddr.add(76).readUtf8String() || "";
                const questRewards = baseAddr.add(640).readUtf8String() || "";
                const questRepeatRewards = baseAddr.add(744).readUtf8String() || "";

                send({
                    type: 'quest_data',
                    data: {
                        subquestName: subquestName,
                        questName: questName,
                        questDesc: questDesc,
                        questRewards: questRewards,
                        questRepeatRewards: questRepeatRewards
                    }
                });

                // block thread and wait for python to return.
                var replacements = null;
                var op = recv('quest_replacements', function(message) {
                    replacements = message.data;
                });
                op.wait();

                // cache result to make instant for this session.
                if (replacements) {
                    questCache.set(questDesc, replacements);

                    // Write replacements back to memory
                    if (replacements.subquestName) {
                        baseAddr.add(20).writeUtf8String(replacements.subquestName);
                    }
                    if (replacements.questName) {
                        baseAddr.add(76).writeUtf8String(replacements.questName);
                    }
                    if (replacements.questDesc) {
                        baseAddr.add(132).writeUtf8String(replacements.questDesc);
                    }
                    if (replacements.questRewards) {
                        baseAddr.add(640).writeUtf8String(replacements.questRewards);
                    }
                    if (replacements.questRepeatRewards) {
                        baseAddr.add(744).writeUtf8String(replacements.questRepeatRewards);
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
