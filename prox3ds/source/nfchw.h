#pragma once
#include <3ds.h>

// Raw access to the New3DS NFC controller (BCM20791) as used by the nfc sysmodule
// (0004013020004002), see NOTES.md for where these values come from.

#define NFC_I2C_DEVID   15

#define NFC_GPIO_REG_PU 0x2000  // output, UPIO pin 1 in the module; high = chip powered (50 ms settle)
#define NFC_GPIO_WAKE   0x1000  // output, UPIO pin 2 (nfc_hal_dm_set_nfc_wake); low = wake asserted
#define NFC_GPIO_IRQ    0x10000 // input, bound to an interrupt by the module

#define NCI_HCIT        0x10    // I2C packet type prefix in front of every NCI packet
#define HCI_HCIT_CMD    0x01    // BT HCI command (Broadcom VSCs, as sent by the module)
#define HCI_HCIT_EVT    0x04    // BT HCI event

Result nfchwOpenGpio(void); // non-blocking, 0xD0401834 = no free session
Result nfchwOpenI2c(void);
void nfchwExit(void);

Result gpioNfcSetDirection(u32 value, u32 mask);         // GPIO cmd 0x2 (SetRegPart1)
Result gpioNfcSetInterruptMask(u32 value, u32 mask);     // GPIO cmd 0x6
Result gpioNfcGetData(u32 mask, u32 *out);               // GPIO cmd 0x7
Result gpioNfcSetData(u32 value, u32 mask);              // GPIO cmd 0x8
Result gpioNfcBindInterrupt(u32 mask, Handle event, s32 priority); // GPIO cmd 0x9
Result gpioNfcUnbindInterrupt(u32 mask, Handle event);   // GPIO cmd 0xA

Result i2cNfcWrite(const void *buf, u32 size);   // I2C cmd 0x14 (WriteDeviceRaw)
Result i2cNfcRead(void *buf, u32 size);          // I2C cmd 0x15 (ReadDeviceRaw), size <= 0x100
