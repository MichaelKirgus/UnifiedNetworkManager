# SNMP MIB files

Drop vendor `.mib` files into this directory — they are mounted read-only
into the snmp-plugin container at `/app/mibs` and added to `snmpwalk`'s MIB
search path (`-M /app/mibs` + `MIBDIRS`).

Standard MIBs (SNMPv2-MIB, IF-MIB, …) already ship with net-snmp inside the
container, so this directory is only needed for vendor-specific definitions.

The plugin's core walks use numeric OIDs and therefore work without any MIB
files; adding MIBs improves human-readable output (resolved names instead of
numeric values) for any future OID-based extensions.
