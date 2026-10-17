/* The wire version, spelled exactly once.
 *
 * V17..V25 hardcoded "RADIOV9" in every format string and in both parsers, so
 * the version lived in roughly thirty string literals across firmware, host and
 * tests. Bumping it by hand is how a firmware comes to emit two different
 * versions on the same link: the parser accepts one spelling while some rarely
 * taken record still prints the old one, and the host's prefix check passes
 * until exactly that record appears.
 *
 * Both parsers and every formatter now derive their prefix from here. The host
 * cannot do the same: it has to know a prefix before it can ask INFO anything,
 * so it carries exactly one copy of its own (host/rejoin_wire.py) and verifies
 * it against the firmware's `wire=` field in INFO. The copy is unavoidable;
 * the check is what keeps it from drifting.
 *
 * `version` in INFO stays the firmware revision (26, continuing V17..V25) and
 * is a different number from this one. Collapsing the two is how a host loses
 * the ability to tell a firmware revision from a protocol revision.
 */
#ifndef RADIO_WIRE_H
#define RADIO_WIRE_H

#define RADIO_WIRE_VERSION 10
#define RADIO_PREFIX "RADIOV10"

/* Kept as a separate name from RADIO_PREFIX so that the compatibility
 * statement in the protocol contract has something to point at: this is the
 * version whose typed verbs V26 inherits and whose predicates it preserves. */
#define RADIO_PREFIX_LINEAGE "RADIOV9"

#endif
