// hook for player login - initializes database with player/sibling data.
// this is triggered when the player logs in with their character.
// (8.1.346492.1: DQXGame.exe+51CF00; was +4F4290 in 8.0)
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    53                    - push ebx                ; 8.1: 'this' moved esi -> ebx
    8B D9                 - mov ebx,ecx
    56                    - push esi
    57                    - push edi
    8B 43 58              - mov eax,[ebx+58]
    85 C0                 - test eax,eax
    74 10                 - je DQXGame.exe+51CF1F
    50                    - push eax
    E8 8B4EBCFF           - call mem_deleteIfNotNull
    83 C4 04              - add esp,04
    C7 43 58 00000000     - mov [ebx+58],00000000
    6A 02                 - push 02
    68 E4000000           - push 000000E4           ; struct grew 0xB8 -> 0xE4 in 8.1
    E8 554EBCFF           - call <allocator>
    ...
    8B 75 08              - mov esi,[ebp+08]        ; a2
    B9 39000000           - mov ecx,39              ; 0x39 dwords = 0xE4 bytes
    F3 A5                 - rep movsd               ; copy a2 into the new struct

    8.1 struct layout (from the inlined constructor):
      +0x18 (24)  player name, char[0x13]
      +0xA4 (164) sibling name, char[0x13]   (was +0x64/100)
      +0xB7 (183) sibling relationship byte  (was +0x77/119)
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
                // _DWORD *__thiscall sub_FD6D10(int *this, const void *a2)
                // this = ECX (implicit), a2 = args[0]

                // args[0] is a2 - pointer to struct pointer
                const structPtrAddr = args[0];

                if (structPtrAddr.isNull()) {
                    return;
                }

                const structAddr = structPtrAddr;

                if (structAddr.isNull()) {
                    return;
                }

                // read player name at struct+24
                const playerName = structAddr.add(24).readUtf8String();

                // read sibling name at struct+164 (0xA4; was +100 before 8.1)
                const siblingName = structAddr.add(164).readUtf8String();

                // read relationship byte at struct+183 (0xB7; was +119 before 8.1)
                const relationshipByte = structAddr.add(183).readU8();

                if (!playerName || !siblingName) {
                    return;
                }

                // send to python async to avoid freezing when doing db operations
                send({
                    type: 'init_player',
                    player_name: playerName,
                    sibling_name: siblingName,
                    relationship_byte: relationshipByte
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
