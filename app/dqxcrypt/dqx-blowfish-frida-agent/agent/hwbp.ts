// HWBP implementation from https://github.com/b0z1 via Frida issue tracker.
const OpenThread = new NativeFunction(Module.findExportByName('kernel32.dll', 'OpenThread')!, 'ulong', ['ulong', 'uchar', 'ulong'])
const CloseHandle = new NativeFunction(Module.findExportByName('kernel32.dll', 'CloseHandle')!, 'uchar', ['ulong'])
const GetThreadContext = new NativeFunction(Module.findExportByName('kernel32.dll', 'GetThreadContext')!, 'uchar', ['ulong', 'pointer'])
const SetThreadContext = new NativeFunction(Module.findExportByName('kernel32.dll', 'SetThreadContext')!, 'uchar', ['ulong', 'pointer'])

type BreakpointCallback = (details: ExceptionDetails) => void

interface Breakpoint {
  address: NativePointer
  callback: BreakpointCallback
  detach: () => void
}

export default new class HardwareBreakpointClass {
  #initialized = false
  #breakpoints: Breakpoint[] = []

  constructor() {
    if (!OpenThread || !CloseHandle || !GetThreadContext || !SetThreadContext) {
      console.error("HardwareBreakpoint initialization failed")
      return
    }

    this.#initialized = true

    Process.setExceptionHandler(details => {
      if (details.type === 'single-step') {
        this.#breakpoints.forEach(bp => {
          if (bp.address.equals(details.address)) {
            bp.callback(details)
          }
        })

        this.#updateContext(details.nativeContext)
        return true
      }
    })
  }

  attach(address: NativePointer, callback: BreakpointCallback): Breakpoint {
    if (!this.#initialized) {
      console.error('Attach failed: Hardwarebreakpoints were not initialized!')
      return null!
    }
    if (this.#breakpoints.length >= 4) {
      console.error('Attach failed: Not more than 4 hardware breakpoints possible!')
      return null!
    }

    const breakpoint: Breakpoint = {
      address,
      callback,
      detach: () => {
        this.#breakpoints.splice(this.#breakpoints.indexOf(breakpoint), 1)
      }
    }

    this.#breakpoints.push(breakpoint)
    this.#refreshContext() // Refresh our hooks

    return breakpoint
  }

  #updateContext(context: NativePointer) {
    let dr7 = 0
    this.#breakpoints.forEach((bp, i) => {
      context.add(4 + i * 4).writePointer(bp.address) // Set DR0-DR3
      dr7 = dr7 | (1 << i * 2)
    })
    context.add(0x18).writeU32(dr7) // Write activation to DR7
    context.add(0xC0).writeU32(context.add(0xC0).readU32() | 0x10000) // Set eflags resume
  }

  #refreshContext() {
    Process.enumerateThreads().forEach(thread => {
      const hThread = OpenThread(0x001F03FF, false ? 1 : 0, thread.id) /*THREAD_ALL_ACCESS = 0x001F03FF*/
      const context = Memory.alloc(0x2CC) /*typedef struct _CONTEXT //size = 0x2CC*/
      context.writeU32(0x10010) /*CONTEXT_DEBUG_REGISTERS = 0x10010*/

      if (GetThreadContext(hThread, context)) {
        this.#updateContext(context)
        SetThreadContext(hThread, context)
      }
      CloseHandle(hThread)
    })
  }
}
