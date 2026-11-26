# ResMed myAir

This integration makes CPAP therapy data from ResMed myAir available in Home Assistant.

## Language

### Account and equipment

**myAir Account**:
The account used to sign in to ResMed myAir and access sleep records and registered CPAP device information.

**CPAP Device**:
The physical therapy machine registered in myAir, identified by its serial number.
_Avoid_: Account, when referring to the machine.

### Sleep records and dates

**Sleep Record**:
The myAir summary of CPAP therapy for an assigned date. A record can exist with zero usage.
_Avoid_: Sleep session, which suggests a single period of use.

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

**Mask On/Off Count**:
The number of mask on/off pairs reported by myAir for a sleep record.

**Mask Leak**:
The rate of air leakage reported by myAir for a sleep record, expressed in liters per minute.

**Total myAir Score**:
The overall score myAir reports for a Sleep Record.

**myAir Score Component**:
The points myAir reports for one scoring category on a Sleep Record. The categories are usage hours, mask seal, events per hour, and mask on/off.
