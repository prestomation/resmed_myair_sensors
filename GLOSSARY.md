# ResMed myAir

This integration makes CPAP therapy data from ResMed myAir available in Home Assistant.

## Language

### Account and equipment

**myAir Account**:
The account used to sign in to ResMed myAir and access sleep records and registered CPAP device information.

**CPAP Device**:
The physical therapy machine registered in myAir, identified by its serial number.
_Avoid_: Account, when referring to the machine.

**Configured CPAP Device**:
The CPAP Device whose serial number a Home Assistant myAir entry is tied to. The integration shows myAir data under the entry's sensors only while that data can be attributed to this device.
_Avoid_: Current device, which can mean whichever device myAir reports now.

### Sleep records and dates

**Sleep Record**:
The myAir summary of CPAP therapy for an assigned date. A record can exist with zero usage.
_Avoid_: Sleep session, which suggests a single period of use.

**Nightly Therapy Timeline**:
The myAir summary and timestamped respiratory and therapy status events for an assigned date. Events in one timeline can occur on both sides of midnight.

**Current Data Date**:
The date assigned by myAir to the latest sleep record, including a record with zero usage.

**Most Recent Sleep Date**:
The latest sleep record date with positive CPAP usage. This date can precede the Current Data Date.
_Avoid_: Last sleep date, which can also mean the Current Data Date.

**Sleep Data Last Collected**:
The CPAP device’s last sleep data report time, as shown in myAir.

### Therapy metrics

**CPAP Usage**:
The total duration of CPAP use reported for a sleep record.

**Apnea-Hypopnea Index (AHI)**:
The rate of apnea and hypopnea events per hour reported by myAir for a sleep record.

**Apnea Index**:
The rate of apnea events per hour of CPAP therapy reported by myAir for a Sleep Record.

**Hypopnea Index**:
The rate of hypopnea events per hour of CPAP therapy reported by myAir for a Sleep Record.

**Time in Apnea**:
The total time in seconds myAir reports as spent in apnea for a Nightly Therapy Timeline.

**Mask On/Off Count**:
The number of mask on/off pairs reported by myAir for a sleep record.

**Mask Leak**:
The rate of air leakage reported by myAir for a sleep record, expressed in liters per minute.

**Total myAir Score**:
The overall score myAir reports for a Sleep Record.

**myAir Score Component**:
The points myAir reports for one scoring category on a Sleep Record. The categories are usage hours, mask seal, events per hour, and mask on/off.
