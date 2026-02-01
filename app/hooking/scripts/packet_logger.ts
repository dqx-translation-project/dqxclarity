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

    // Known op_code + marker combinations from DataPacketRouter.
    // Each key is (op_code << 16) | (marker_byte1 << 8) | marker_byte2.
    var KNOWN_PACKETS = {};
    KNOWN_PACKETS[0x21e535] = true;  // story_so_far window opened
    KNOWN_PACKETS[0x21be01] = true;  // story_so_far text
    KNOWN_PACKETS[0x21a83c] = true;  // npc dialogue
    KNOWN_PACKETS[0x216dd4] = true;  // walkthrough text
    KNOWN_PACKETS[0x5d2b15] = true;  // quest text
    KNOWN_PACKETS[0x5dcc51] = true;  // quest text
    KNOWN_PACKETS[0x875408] = true;  // server list
    KNOWN_PACKETS[0x878408] = true;  // server list
    KNOWN_PACKETS[0x876185] = true;  // important notice
    KNOWN_PACKETS[0x0d9ee1] = true;  // team list
    KNOWN_PACKETS[0x0dee25] = true;  // party message
    KNOWN_PACKETS[0x0d2711] = true;  // team message
    KNOWN_PACKETS[0x0d7690] = true;  // private message
    KNOWN_PACKETS[0x0d755d] = true;  // room message
    KNOWN_PACKETS[0x3d16b6] = true;  // team quest
    KNOWN_PACKETS[0x52ee25] = true;  // entity
    KNOWN_PACKETS[0x664cc2] = true;  // memory main list
    KNOWN_PACKETS[0x66da30] = true;  // memory chapter list
    KNOWN_PACKETS[0x664569] = true;  // memory sub chapter list
    KNOWN_PACKETS[0x79994b] = true;  // master quest
    KNOWN_PACKETS[0x03f7f5] = true;  // party list
    KNOWN_PACKETS[0x466bb8] = true;  // weekly request
    KNOWN_PACKETS[0x4b4569] = true;  // mytown amenity
    KNOWN_PACKETS[0x05ea73] = true;  // concierge name

    // Entity packet (0x52ee25) sub-filter: only forward known entity types.
    // The entity type byte is at payload + 14 (3 bytes op_code+marker, then 11 bytes into entity data).
    var ENTITY_KEY = 0x52ee25;
    var KNOWN_ENTITY_TYPES = {};
    KNOWN_ENTITY_TYPES[0x01] = true;  // player
    KNOWN_ENTITY_TYPES[0x02] = true;  // monster
    KNOWN_ENTITY_TYPES[0x04] = true;  // npc
    KNOWN_ENTITY_TYPES[0x85] = true;  // fellow

    // Payload offset by size_identifier (lower nibble of byte 0 for data packets).
    //   0: 1-byte header + 1-byte size  -> payload at offset 2
    //   1: 1-byte header + 2-byte size  -> payload at offset 3
    //   2: 1-byte header + 4-byte size  -> payload at offset 5
    //   3: 1-byte header + 4-byte size  -> payload at offset 5
    var PAYLOAD_OFFSETS = [2, 3, 5, 5];

    // Cache for player entity name translations (origName -> {nameLen, nameBytes})
    var playerNameCache = {};
    var ORIGINAL_SIZE_HEADERS = [2, 3, 4, 4];

    function readPayloadSize(ptr, sizeIdentifier) {
        if (sizeIdentifier === 0) {
            return ptr.add(1).readU8();
        } else if (sizeIdentifier === 1) {
            return ptr.add(1).readU16();
        } else {
            return ptr.add(1).readU32();
        }
    }

    function writeSizeHeader(ptr, size) {
        if (size <= 0xFF) {
            ptr.writeU8(0x00);
            ptr.add(1).writeU8(size);
            return 2;
        } else if (size <= 0xFFFF) {
            ptr.writeU8(0x01);
            ptr.add(1).writeU16(size);
            return 3;
        } else if (size <= 0xFFFFFF) {
            ptr.writeU8(0x02);
            ptr.add(1).writeU32(size);
            return 5;
        } else {
            ptr.writeU8(0x03);
            ptr.add(1).writeU32(size);
            return 5;
        }
    }

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

                // Filter: only forward data packets with known op_code + marker to Python.
                // This avoids expensive IPC round-trips for packets we don't handle.
                const firstByte = packetDataPtr.readU8();
                const packetType = firstByte >> 4;

                // only data packets (upper nibble 0) are processed by Python
                if (packetType !== 0) {
                    return;
                }

                const sizeIdentifier = firstByte & 0x0F;
                if (sizeIdentifier > 3) {
                    return;
                }

                const payloadOffset = PAYLOAD_OFFSETS[sizeIdentifier];

                // need at least 3 payload bytes (op_code + marker) to identify the packet
                if (packetLength < payloadOffset + 3) {
                    return;
                }

                // read op_code (1 byte) + marker (2 bytes) and combine into a 24-bit key
                const opCode = packetDataPtr.add(payloadOffset).readU8();
                const marker1 = packetDataPtr.add(payloadOffset + 1).readU8();
                const marker2 = packetDataPtr.add(payloadOffset + 2).readU8();
                const key = (opCode << 16) | (marker1 << 8) | marker2;

                if (!KNOWN_PACKETS[key]) {
                    return;
                }

                // for entity packets, also filter by entity type byte
                var entityType = 0;
                if (key === ENTITY_KEY) {
                    var entityTypeOffset = payloadOffset + 14;
                    if (packetLength < entityTypeOffset + 1) {
                        return;
                    }
                    entityType = packetDataPtr.add(entityTypeOffset).readU8();
                    if (!KNOWN_ENTITY_TYPES[entityType]) {
                        return;
                    }
                }

                // player entity cache path
                var origName = null;
                if (key === ENTITY_KEY && entityType === 0x01) {
                    var nameStartOffset = payloadOffset + 581;
                    if (packetLength >= nameStartOffset + 1) {
                        var payloadSize = readPayloadSize(packetDataPtr, sizeIdentifier);
                        var origNameLen = packetDataPtr.add(payloadOffset + 577).readU32();
                        if (origNameLen > 0 && payloadOffset + 581 + origNameLen <= packetLength) {
                            origName = packetDataPtr.add(nameStartOffset).readUtf8String(origNameLen - 1);

                            var cached = playerNameCache[origName];
                            if (cached) {
                                // cache hit: rebuild packet in JS, skip Python
                                var newPayloadSize = payloadSize - origNameLen + cached.nameLen;

                                // determine new size header length
                                var newSizeHeaderLen;
                                if (newPayloadSize <= 0xFF) {
                                    newSizeHeaderLen = 2;
                                } else if (newPayloadSize <= 0xFFFF) {
                                    newSizeHeaderLen = 3;
                                } else {
                                    newSizeHeaderLen = 5;
                                }

                                // remainder after this entity's payload (other packets in buffer)
                                var payloadEnd = payloadOffset + payloadSize;
                                var remainderLen = packetLength - payloadEnd;

                                // remaining entity data after name
                                var afterNameOffset = nameStartOffset + origNameLen;
                                var afterNameLen = payloadEnd - afterNameOffset;

                                var totalLen = newSizeHeaderLen + newPayloadSize + remainderLen;
                                var newBuf = Memory.alloc(totalLen);

                                // write size header
                                writeSizeHeader(newBuf, newPayloadSize);

                                // copy 577 bytes: op_code + marker + entity header up to name_length
                                Memory.copy(newBuf.add(newSizeHeaderLen), packetDataPtr.add(payloadOffset), 577);

                                // write translated name length
                                newBuf.add(newSizeHeaderLen + 577).writeU32(cached.nameLen);

                                // write translated name bytes
                                newBuf.add(newSizeHeaderLen + 581).writeByteArray(cached.nameBytes);

                                // copy remaining entity data after name
                                if (afterNameLen > 0) {
                                    Memory.copy(
                                        newBuf.add(newSizeHeaderLen + 581 + cached.nameLen),
                                        packetDataPtr.add(afterNameOffset),
                                        afterNameLen
                                    );
                                }

                                // copy remainder
                                if (remainderLen > 0) {
                                    Memory.copy(
                                        newBuf.add(newSizeHeaderLen + newPayloadSize),
                                        packetDataPtr.add(payloadEnd),
                                        remainderLen
                                    );
                                }

                                var originalSize = payloadSize + ORIGINAL_SIZE_HEADERS[sizeIdentifier];
                                this.originalSize = originalSize;
                                this.newBuffer = newBuf;
                                args[0] = newBuf;
                                return;
                            }
                        }
                    }
                }

                const packetData = packetDataPtr.readByteArray(packetLength);

                // send to python and wait for response
                send({
                    type: 'packet_data',
                }, packetData);

                // block until python responds with modified packet (or null)
                var modifiedData = null;
                var originalSize = null;

                recv('modified_packet', function(message, data) {
                    if (message.modified && data) {
                        modifiedData = data;
                        originalSize = message.size;
                    }
                }).wait();

                // cache translated player name from Python response
                if (modifiedData !== null && origName !== null) {
                    var modBytes = new Uint8Array(modifiedData);
                    // determine modified size header length from first byte
                    var modFirstByte = modBytes[0];
                    var modSizeHeaderLen;
                    if (modFirstByte === 0x00) {
                        modSizeHeaderLen = 2;
                    } else if (modFirstByte === 0x01) {
                        modSizeHeaderLen = 3;
                    } else {
                        modSizeHeaderLen = 5;
                    }

                    var nameLenOff = modSizeHeaderLen + 577;
                    if (modBytes.length >= nameLenOff + 4) {
                        var transNameLen = modBytes[nameLenOff]
                            | (modBytes[nameLenOff + 1] << 8)
                            | (modBytes[nameLenOff + 2] << 16)
                            | (modBytes[nameLenOff + 3] << 24);
                        var nameOff = modSizeHeaderLen + 581;
                        if (transNameLen > 0 && modBytes.length >= nameOff + transNameLen) {
                            var nameSlice = modifiedData.slice(nameOff, nameOff + transNameLen);
                            playerNameCache[origName] = {
                                nameLen: transNameLen,
                                nameBytes: nameSlice
                            };
                        }
                    }
                }

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
