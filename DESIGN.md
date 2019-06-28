Tox extensions sit on top of the custom lossless packets from toxcore. Within a packet they have the following format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TOXEXT_MAGIC                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         TOXEXT_SEGMENT                        +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         TOXEXT_SEGMENT                        +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                              ...                              +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Pretty simple, a magic to identify the custom packet as a toxext packet and then a bunch of segments. We decided to have segments instead of just doing one packet per-extension as we envision each extension using only a small amount of data. If many extensions are being used at once it's forseeable that all data associated with a single message will fit in 1 or 2 tox packets.

A segment is defined as

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       SEGMENT_TYPE      |     SEGMENT_SIZE    |               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+               +
|                          SEGMENT_DATA                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Sizes were derived by figuring out how much we need for the max segment size (log_2(TOXEXT_MAX_PACKET_SIZE)) and then packing type into the next reasonble byte boundary. Keep in mind that identifiers have padding on lots of other packets now, but the segment packet is the one that comes up the most so we just pad on the other packet types

SEGMENT_TYPE is either one of toxext's predefined types or an extension id. We will get into extension id's a little more in a bit

ToxExt comes with 3 pre-defined packets. NEGOTIATE, NEGOTIATE_RESPONSE, and REVOKE.

Negotiation is a crucial part of the ToxExt infrastructure. Each extension is identified with a 16 byte UUID. As part of negotiation we tell our friends what extensions we have as well as how we identify them. We then use that identifier for all future communication with that friend until we re-negotiate.

The negotiation packet has the following
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    TOXEXT_PROTOCOL_VERSION                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                                                               +
|                                                               |
+                              UUID                             +
|                                                               |
+                                                               +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      MY_IDENTIFIER      | PAD |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Note that MY_IDENTIFIER must start at 3 or higher since 0/1/2 are reserved identifiers for toxext's internal packets. It's okay though, these are handed out by the ToxExt library

When a negotiation request is received we respond with the following (where C is for compatible)

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     YOUR_IDENTIFIER     |      MY_IDENTIFIER      |C|   PAD   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

Sure we're wasting 7 bits of data but it makes parsing easier since our data lines up on byte boundaries.

If we decide that we don't want to support an extension anymore we send our friend a revokation packet that looks like this
```
 0                   1
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      MY_IDENTIFIER      | PAD |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

An extension message can have whatever it wants in it, as long as it reports the correct size in the segment block.

The ToxExt library provides an API for extensions to append their packet segment to an overall ToxExt packet. The ToxExt packet may wrap several underlying toxcore custom lossless packets. Each extension message must fit within a toxcore packet as we didn't want to have to cache half-formed messages on the receiver side
