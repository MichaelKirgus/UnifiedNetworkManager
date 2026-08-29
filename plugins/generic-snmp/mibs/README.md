# SNMP MIB files (manual debugging only)

Drop vendor `.mib` files into this directory — it is mounted read-only into
the generic-snmp-plugin container at `/app/mibs`.

The plugin itself queries **numeric OIDs** over native UDP
(`@unm/snmp-client`, no CLI, no MIB parsing), so no MIB file is required for
normal operation. This volume exists purely to make manual debugging easier —
e.g. running `snmpwalk -M /app/mibs` from a host that has net-snmp installed:

```sh
# symbolic names instead of numeric OIDs (host-side, needs net-snmp CLI)
snmpwalk -v2c -c public <device> -M /path/to/plugins/generic-snmp/mibs 1.3.6.1.2.1.2
```

Standard MIBs (SNMPv2-MIB, IF-MIB, …) are not needed at runtime either — the
plugin never resolves symbolic names.
