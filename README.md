# Overview
Designing this with IOT in mind. Most webservers willing to collect data from
devices prefer talking https. Securing communication to-and-from smaller
footprint devices (like particle.io Photon etc.) and standard web servers doing
interesting stuff with this data (glowfi.sh, thingspeak.com, etc) is the goal.
There is a hard limitation you hit with https and that dictates that you have
about 50kB of meemory allocated for it. This is because of huge
Certificate chains that get shipped from https servers.

In all this, lack of a readily available plug and play httpsclient brings us
here. Integrating MatrixSSL with a standard TCP client seemed like a good
starting point.

Any feedback (especially critical) and contributions are welcome!

# Building it locally with spark firmware

Assuming you are comfortable using this library: https://github.com/spark/firmware
- Clone the httpsclient-particle
- Copy the contents of the firmware directory into the above firmware/user/src/ directory of the spark firmware library.
- Pick one of the files in the examples directory. And copy it into user/src directory.
- Modify the first line of the example to remove the path prefix (needed only for web IDE):  
  ````#include "httpsclient-particle.h"````
- Delete/relocate the examples folder (local build won't succeed if it's left there)
- Goto firmware/main/ of the spark firmware directory again. And build it (Again, instructions for this are at https://github.com/spark/firmware) - don't forget `PLATFORM=photon`

# Current State
What's here is a semi-stable working httpsclient that can make requests from
the particle photon board to webservers running https. The client
implementation is simple, and as of now can handle 1 connection at any given
time. Other features (for now) are:

## Adhere to security
- TLS 1.2
- RSA 2048bit key length
- Slow is OK, but secure is a must!
- Ramping this up to 4096bit key length ought to be tested, and this may just
  consume a whole lot of memory (AGAIN, especially the server certificates).
  Writing the certificate chains to flash is an option.

## Small memory footprint:
- Client only
- Single session
- No Client Authentication
- Static memory allocation

## License:
GPL, as matrixSSL-open library is under GPL.

# A few important changes from MatrixSSL:
- Make the ssl structure static, as we are just using a single session.
- Header file compatibility with particle.io build system. This means
  adjusting the include paths (this needs to be fixed).
- Keep SSL in-out buffers static.

# TODO:
- Add and test Elliptic curve support (This will take up a larger footprint)
- Find a better way to seed entropy. Currently takes the last 8 bits of the
  system microsecond counter.
- Add a feature to generate header files from RSA keys, etc. After this remove
  samplecerts from the repository (?)
- Inspect all dynamic memory allocations and check for memory leaks (all psMallocs)
- Add tests!! MatrixSSL tests are heavy handed. Need to carefully go through these
  and add the ones needed.
- Find a better way to include header files
- A memory pool implementation (if needed), especially to give back the obscene
  amount of memory SSL Certificates consume.
- The only way to currently print and trace info on the particle.io's photon is
  by using Serial (written in c++). This is a bit painful if the rest of your
  library is in C, necessary '.h' file needs to be wrapped with extern C
  wrappers to get it to build correctly.
- Last but no way the least, a thorough security AUDIT.
- Decide on keeping this repository in sync with MatrixSSL-open. This isn't
  trivial as keeping up with Photon/Arduino/MatrixSSL build systems maybe be a
  handful.
