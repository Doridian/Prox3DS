#pragma once
#include <3ds.h>

// Field level meter (field.c): how strongly the card on the reader loads the 13.56 MHz field, the
// Prox3DS take on the pm3's antenna volts. The RX samples the carrier as I/Q; its amplitude drops when a
// card couples into the field (empty ~166, an NTAG placed well ~150 on the test console). Shown as bars
// in the header while an NFC-A card session has the field on.

void fieldArm(void);    // in the job, the ROM just activated an NFC-A card: the field is up, sample it
void fieldDisarm(void); // a new chip image or the chip off: no field to sample
void fieldPoll(void);   // from the monitor transport: a sample every few hundred ms while armed
// Job end, field still on, before the chip goes off: once per app run, calibrate the I/Q offset
// (field toggles, circle fit; resets the card).
void fieldJobEnd(void);

bool fieldTuneSample(void); // the Tuning screen's job: one sample now (false = no field / junk)

#define FIELD_BARS 5
// UI: bars 0..FIELD_BARS of the last reading, -1 = none recent. live = the field is on now.
int fieldBars(bool *live);
// The Tuning gauge: how much the card loads the field, 0..1 of full scale (smoothed); live as above.
float fieldGauge(bool *live);
float fieldLevel(float *empty); // the smoothed vector length (0 = none yet) and the learned empty level
