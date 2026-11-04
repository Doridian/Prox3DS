#include "nfchw.h"

static Handle i2cHandle;
static Handle gpioHandle;

// srvGetServiceHandle normally blocks while a service's sessions are all in use,
// so open non-blocking and let the caller retry.
static Result openService(Handle *out, const char *name)
{
	srvSetBlockingPolicy(true);
	Result res = srvGetServiceHandle(out, name);
	srvSetBlockingPolicy(false);
	return res;
}

Result nfchwOpenGpio(void) { return gpioHandle ? 0 : openService(&gpioHandle, "gpio:NFC"); }
Result nfchwOpenI2c(void)  { return i2cHandle ? 0 : openService(&i2cHandle, "i2c::NFC"); }

void nfchwExit(void)
{
	if (i2cHandle) svcCloseHandle(i2cHandle);
	if (gpioHandle) svcCloseHandle(gpioHandle);
	i2cHandle = gpioHandle = 0;
}

static Result gpioCmd2(u16 cmd, u32 a, u32 b)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = IPC_MakeHeader(cmd, 2, 0);
	cmdbuf[1] = a;
	cmdbuf[2] = b;
	Result res = svcSendSyncRequest(gpioHandle);
	return R_FAILED(res) ? res : (Result)cmdbuf[1];
}

Result gpioNfcSetDirection(u32 value, u32 mask)     { return gpioCmd2(0x2, value, mask); }
Result gpioNfcSetInterruptMask(u32 value, u32 mask) { return gpioCmd2(0x6, value, mask); }
Result gpioNfcSetData(u32 value, u32 mask)          { return gpioCmd2(0x8, value, mask); }

Result gpioNfcBindInterrupt(u32 mask, Handle event, s32 priority)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = IPC_MakeHeader(0x9, 2, 2);
	cmdbuf[1] = mask;
	cmdbuf[2] = priority;
	cmdbuf[3] = IPC_Desc_SharedHandles(1);
	cmdbuf[4] = event;
	Result res = svcSendSyncRequest(gpioHandle);
	return R_FAILED(res) ? res : (Result)cmdbuf[1];
}

Result gpioNfcUnbindInterrupt(u32 mask, Handle event)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = IPC_MakeHeader(0xA, 1, 2);
	cmdbuf[1] = mask;
	cmdbuf[2] = IPC_Desc_SharedHandles(1);
	cmdbuf[3] = event;
	Result res = svcSendSyncRequest(gpioHandle);
	return R_FAILED(res) ? res : (Result)cmdbuf[1];
}

Result gpioNfcGetData(u32 mask, u32 *out)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = IPC_MakeHeader(0x7, 1, 0);
	cmdbuf[1] = mask;
	Result res = svcSendSyncRequest(gpioHandle);
	if (R_FAILED(res)) return res;
	*out = cmdbuf[2];
	return (Result)cmdbuf[1];
}

Result i2cNfcWrite(const void *buf, u32 size)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	cmdbuf[0] = IPC_MakeHeader(0x14, 2, 2);
	cmdbuf[1] = NFC_I2C_DEVID;
	cmdbuf[2] = size;
	cmdbuf[3] = IPC_Desc_StaticBuffer(size, 1);
	cmdbuf[4] = (u32)buf;
	Result res = svcSendSyncRequest(i2cHandle);
	return R_FAILED(res) ? res : (Result)cmdbuf[1];
}

Result i2cNfcRead(void *buf, u32 size)
{
	u32 *cmdbuf = getThreadCommandBuffer();
	u32 *staticbufs = getThreadStaticBuffers();
	u32 saved[2] = { staticbufs[0], staticbufs[1] };

	cmdbuf[0] = IPC_MakeHeader(0x15, 2, 0);
	cmdbuf[1] = NFC_I2C_DEVID;
	cmdbuf[2] = size;
	staticbufs[0] = IPC_Desc_StaticBuffer(size, 0);
	staticbufs[1] = (u32)buf;

	Result res = svcSendSyncRequest(i2cHandle);

	staticbufs[0] = saved[0];
	staticbufs[1] = saved[1];
	return R_FAILED(res) ? res : (Result)cmdbuf[1];
}
