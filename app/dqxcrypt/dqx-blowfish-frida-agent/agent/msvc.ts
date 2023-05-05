type AllocatorFn = (size: number) => NativePointer
type DeallocatorFn = (ptr: NativePointer) => void

// A 32-bit MSVC std::vector holder, solely for the purpose of blowfish decryption.
// This is not general-purpose enough for other usage.
export class MSVCVector {
    #alloc: AllocatorFn
    #dealloc: DeallocatorFn
    #head: NativePointer
    #backing: NativePointer

    constructor(alloc: AllocatorFn, dealloc: DeallocatorFn) {
        this.#alloc = alloc;
        this.#dealloc = dealloc;
        this.#head = this.#alloc(12);
        this.#backing = ptr(0);
    }

    reserve(size: number): void {
        // Dealloc old backing
        if(!this.#backing.compare(ptr(0))) {
            this.#dealloc(this.#backing);
            this.#backing = ptr(0);
        }

        // Alloc new backing buf
        this.#backing = this.#alloc(size);

        // Set the head pointers.
        this.set_start(this.#backing);
        this.set_end(this.#backing);
        this.set_cap(this.#backing.add(size));
    }

    // Resize to `size` (e.g. essentially allocate a vector of null bytes of `size`)
    resize(size: number): void {
        this.reserve(size);
        for(let i = 0; i < size; i++) {
            this.#backing.add(i).writeU8(0);
        }
        this.set_end(this.get_start().add(size));
    }

    ptr(): NativePointer {return this.#head; }
    get_start(): NativePointer { return this.#head.add(0x00).readPointer(); }
    get_end(): NativePointer { return this.#head.add(0x04).readPointer(); }
    get_cap(): NativePointer { return this.#head.add(0x08).readPointer(); }
    set_start(ptr: NativePointer): NativePointer { return this.#head.add(0x00).writePointer(ptr); }
    set_end(ptr: NativePointer): NativePointer { return this.#head.add(0x04).writePointer(ptr); }
    set_cap(ptr: NativePointer): NativePointer { return this.#head.add(0x08).writePointer(ptr); }

    size(): number { return this.get_end().sub(this.get_start()).toUInt32(); }

    setData(data: ArrayBuffer): void {
        this.reserve(data.byteLength);
        this.#backing.writeByteArray(data);
        this.set_end(this.get_start().add(data.byteLength));
    } 
}