# hooking module

[Frida](https://frida.re/) is used here as the hooking toolkit for redirecting game code to ours. It's a powerful reverse engineering orchestration tool that has all of the hooking logic built into it.

[Documentation](https://frida.re/docs/javascript-api/)

It runs javascript/typescript inside of the client while creating a bridge outside of the client to Python to run any Python logic. For dqxclarity, all of the memory calls are done in Typescript and then passed to Python for the actual processing.

To create a new hook:

- Create a script in the scripts/ folder that defines how to hook the function you're interested in, pulling any string or data values out and sending them to Python for processing. These scripts are untyped Typescript files
    - Typing them requires them to be transpiled, which is overhead we aren't doing
- Create a python module in the hooks/ folder that receives the data from Frida and processing it, then sends a signal back to Frida that it has completed
- The Typescript file should intake the results and do whatever you need it to do
- Add the hook to `hook.py` in the appropriate category to have dqxclarity load it at runtime
