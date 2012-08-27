==================
Stripe CTF Level 8
==================

My script to crack the level 8 of the Stripe CTF Challenge 2012. In order to run
this, you have to adjust the ``SERVER_HOST`` to your level 2 server you put the
script on. You may also want to adjust the ``CONFIRMATIONS`` value to a
reasonable number. 3 works fine, but may take a really long time on an
overloaded server.

Other than that, just copy it onto the server, run::

    ./level8.py

and grab a cup of coffee. Enjoy.

Architecture
============

The program spawns a threaded TCP server that acts like a dumb HTTP server which
only real job is to keep track of the difference in the incoming TCP source
ports (deltas). The main thread runs the client which fires requests to the
PasswordDB server with the local server provided as webhook. It then waits for
the local server to report the source port back (using a synchronized Queue,
which is pretty awesome). The deltas indicate how many chunk servers were
contacted, ie. how many chunks are valid. There is some magic going on to make
sure a certain amount of confirmations was collected before a chunk is
considered correct.

Caveats
=======

    * This runs very slowly if the PasswordDB server is hammered, because it's
      hard to get a reliable delta.
    * This fails if the password contains a "000" chunk as any but the first
      chunk. (This could be fixed.)
