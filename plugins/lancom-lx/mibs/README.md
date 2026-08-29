# LANCOM plugin MIBs (manual debugging only)

Drop vendor MIB files into this directory — it is mounted read-only at
`/app/mibs` inside the container.

The plugin itself queries **numeric OIDs** over native UDP
(`@unm/snmp-client`, no CLI, no MIB parsing), so no MIB file is required for
normal operation. A MIB here only makes manual debugging easier — e.g. running
`snmpwalk -M /app/mibs <device> 1.3.6.1.4.1.2356.13.1` from a host that has
the net-snmp CLI installed, to see symbolic names instead of numeric OIDs:

- LCOS-LX-MIB — e.g. from a LANCOM release package, such as
  https://ftp.lancom.de/LANCOM-Releases/LC-LX-6500/ (the LX-6500 MIB is the
  superset covering all LX-Series access points).
