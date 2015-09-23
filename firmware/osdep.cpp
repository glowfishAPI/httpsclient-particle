#include "coreApi.h"
#include "rtc_hal.h"
#include "spark_wiring_ticks.h"
#include "application.h"

/******************************************************************************/
#ifdef METAL
/******************************************************************************/
/******************************************************************************/
/*
  RAW TRACE FUNCTIONS
*/
/******************************************************************************/

int osdepTraceOpen(void)
{
  return PS_SUCCESS;
}

void osdepTraceClose(void)
{
}

void _psTrace(char *msg)
{
  Serial.println(msg);
}

/* message should contain one %s, unless value is NULL */
void _psTraceStr(char *message, char *value)
{
  if (value) {
    Serial.print(message); Serial.println(value);
  } else {
    Serial.print(message);
  }
}

/* message should contain one %d */
void _psTraceInt(char *message, int32 value)
{
  _psTrace(message);
  Serial.println(value);
}

/* message should contain one %p */
void _psTracePtr(char *message, void *value)
{
}


int osdepTimeOpen(void)
{
  return PS_SUCCESS;
}

void osdepTimeClose(void)
{

}

int32 psGetTime(psTime_t *t, void *userPtr)
{
  return HAL_RTC_Get_UnixTime();
}

int32 psDiffMsecs(psTime_t then, psTime_t now, void *userPtr)
{
  return 0;
}

int64_t psDiffUsecs(psTime_t then, psTime_t now)
{
  return 0;
}

int32 psCompareTime(psTime_t a, psTime_t b, void * userPtr)
{
  return 0;
}

//Entropy Functions

#define	MAX_RAND_READS		1024

static int32 urandfd = -1;
static int32 randfd = -1;

int osdepEntropyOpen(void)
{
  return PS_SUCCESS;
}

void osdepEntropyClose(void)
{
}

int32 psGetEntropy(unsigned char *bytes, uint32 size, void *userPtr) {
  // TODO: Assuming size of random return is 4 bytes
  unsigned int i = 0;
  unsigned char* where = bytes;
  for (i = 0; i < size/sizeof(int); i++) {
    *where = (unsigned char) (micros() & 0xff);
    where++;
  }
  return size;
}

#endif
