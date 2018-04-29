# shellcode_harness

I'm not publishing this at this time because I realized that the implementation was very
much modeled after some classroom snippets of C code that I'm not sure ever open 
sourced or not.  This is mostly me just being careful about licensing issues, there is really 
nothing special to this, and wouldn't take much effort to re-create. Basically, you just need 
something to listen on a network port for shellcode and then try to execute it: 
1. Listen to TCP Port #
2. Accept incoming connections
3. Copy content of connection into an executable buffer. 
4. Call a function pointer that points at the start of the executable buffer. 

I guess the 'tricky' part (if you can call it that) is figuring out when all the shellcode has 
been sent; frequently programs terminate reading input on `\n` (`0x0A`) and most shellcode
samples will avoid having this byte, so it's a good place to start. 