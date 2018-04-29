# MPTCP Tools
This repository contains code and resources from my M.S. thesis 
["Why does MPTCP have to make things so complicated?": cross-path NIDS evasion and countermeasures](https://calhoun.nps.edu/handle/10945/50546 ).
The title is an Avril Lavigne reference (the song seemed appropriate when reading RFC 6824), but 
during the review process it unfortunately got grammared enough to make it less recognizable. 

Disclaimer: Everything in here is experimental and is more proof-of-concept than anything intended to 
be actively used. **This is most definitely NOT the production code you're looking for!** 

## Organization
### `red_dev`
This directory is for more offensive minded code, and has a tool / port-forwarder that will 
break up TCP streams into 1-byte chunks. With the right kernel and settings under the hood, 
this will let you split traffic across multiple transport layer paths (TCP connections/MPTCP 
subflows). 

### `blue_dev`
This directory is for defensive and network traffic analysis minded code. The stuff in here 
is exceedingly experimental and proof-of-concepty. 

### `pcaps`
These are some sample pcaps of TCP sessions that do MPTCP session-splicing (AKA cross-path NIDS
fragmentation). They're organized by the chapter of the thesis they correspond to, and will 
hopefully be helpful for anyone interested in reproducing the results. 


## License
This is open-source under GPL v2, mostly because some stuff in the `blue_dev` directory 
was created from some Snort++ examples. 


