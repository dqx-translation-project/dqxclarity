// hook for player login - initializes database with player/sibling data.
// this is triggered when the player logs in with their character.
/*
    55                    - push ebp
    8B EC                 - mov ebp,esp
    56                    - push esi
    8B F1                 - mov esi,ecx
    57                    - push edi
    8B 46 58              - mov eax,[esi+58]
    85 C0                 - test eax,eax
    74 10                 - je DQXGame.exe+422C8E
    50                    - push eax
    E8 9CAEC1FF           - call DQXGame.exe+3DB20
    83 C4 04              - add esp,04
    C7 46 58 00000000     - mov [esi+58],00000000
    6A 02                 - push 02
    68 B0000000           - push 000000B0
    E8 F6ADC1FF           - call DQXGame.exe+3DA90
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

                // read sibling name at struct+100
                const siblingName = structAddr.add(100).readUtf8String();

                // read relationship byte at struct+119
                const relationshipByte = structAddr.add(119).readU8();

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
