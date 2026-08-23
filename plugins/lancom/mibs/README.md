# LANCOM plugin MIBs

Drop vendor MIB files into this directory — it is mounted read-only at
`/app/mibs` inside the container and passed to net-snmp via `MIBDIRS`.

The plugin itself queries **numeric OIDs** (see `src/lcosOids.ts`), so no MIB
file is required for normal operation. A MIB here only makes manual
debugging with `snmpwalk -On` vs symbolic names easier:

- LCOS-LX-MIB — e.g. from a LANCOM release package, such as
  https://ftp.lancom.de/LANCOM-Releases/LC-LX-6500/ (the LX-6500 MIB is the
  superset covering all LX-Series access points).
