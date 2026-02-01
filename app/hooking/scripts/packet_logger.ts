// hook for intercepting post-decrypted packets.
/*
    8B EC                 - mov ebp,esp
    83 EC ??              - sub esp,??
    A1 ?? ?? ?? ??        - mov eax,[????????]
    33 C5                 - xor eax,ebp
    89 45 ??              - mov [ebp+??],eax
    83 7D ?? ??           - cmp dword ptr [ebp+??],??
    53                    - push ebx
    8B 5D ??              - mov ebx,[ebp+??]
    56                    - push esi
    8B F1                 - mov esi,ecx

    int __thiscall ParseNetworkPacket(_QWORD *this, unsigned __int8 *a2, unsigned int a3)
    - this (ECX): connection_object
    - a2 (args[0]): packet_data
    - a3 (args[1]): packet_length
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
                // int __thiscall ParseNetworkPacket(
                //     _QWORD *this,        // ECX - connection_object
                //     unsigned __int8 *a2, // args[0] - packet_data
                //     unsigned int a3)     // args[1] - packet_length
                // returns number of bytes read from packet.
                //
                // there is some function higher up the stack that calls this
                // and iterates over the packet stream, but this is low enough
                // to where can modify the incoming data directly without fear
                // of data corruption (other than our own mistakes).

                const packetDataPtr = args[0];

                // packet size is only used to determine if there is data in
                // the buffer. it serves no other purpose for this function.
                // we choose not to update it as it doesn't matter, but this
                // is here for completeness.
                const packetLength = args[1].toUInt32();

                // sanity check on packet length
                if (packetLength === 0) {
                    return;
                }

                const packetData = packetDataPtr.readByteArray(packetLength);

                // send to python and wait for response
                send({
                    type: 'packet_data',
                }, packetData);

                // block until python responds with modified packet (or null)
                let modifiedData = null;
                let originalSize = null;

                recv('modified_packet', function(message, data) {
                    if (message.modified && data) {
                        modifiedData = data;
                        originalSize = message.size;
                    }
                }).wait();

                // we return the original size as we may alter the packet size
                // to be smaller or larger depending on translation. why this is
                // important is because we create a new buffer for our data and
                // override this iteration's args[0], but do not touch the stack
                // context; doing so has caused issues with the offset unexpectedly
                // jumping around that I can't figure out how to get to work correctly.
                // I suspect because we are in the middle of a loop and the caller
                // is doing its own handling somewhere. another important thing to
                // note is that this is what was *read*, which is not the full size
                // of the packet, but a segment of the packet. this logic is
                // handled on the python side.
                this.originalSize = originalSize;

                if (modifiedData !== null) {
                    const newBuffer = Memory.alloc(modifiedData.byteLength);
                    newBuffer.writeByteArray(modifiedData);

                    // keep buffer alive for function lifetime
                    this.newBuffer = newBuffer;

                    // update stack argument to point to new buffer just for
                    // this iteration.
                    args[0] = newBuffer;
                }
            } catch (e) {
                send({
                    type: 'error',
                    payload: `[${hookName}] onEnter error: ${e.message}`
                });
            }
        },
        onLeave: function (retval) {
            // only modify the return value if we sent our own packet.
            if (this.originalSize) {
                retval.replace(ptr(this.originalSize));
            }
        }
    });
})();
