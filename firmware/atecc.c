#include <fx2lib.h>
#include <fx2delay.h>
#include <fx2regs.h>
#include <fx2i2c.h>
#include "glasgow.h"

enum {
  ATECC_OP_NONCE   = 0x16,
  ATECC_OP_SIGN  = 0x41,
  ATECC_OP_GENKEY = 0x40,
};

void crc16(uint8_t length, const uint8_t *data, uint8_t *crc)
{
  uint16_t crc_register = 0;
  uint16_t polynom = 0x8005;
  uint8_t shift_register;
  uint8_t data_bit, crc_bit;
  uint8_t i;

  for (i = 0; i < length; i++)
  {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
    {
      data_bit = (data[i] & shift_register) ? 1 : 0;
      crc_bit = crc_register >> 15;
      crc_register <<= 1;
      if (data_bit != crc_bit)
      {
        crc_register ^= polynom;
      }
    }
  }
  crc[0] = (uint8_t)(crc_register & 0x00FF);
  crc[1] = (uint8_t)(crc_register >> 8);
}

void atecc_idle() {
    i2c_start(I2C_ADDR_ATECC<<1);
    i2c_write("\x02", 1);
	//smb_write( I2C_ADDR_ATECC508A, "\x02", 1);
}

bool atecc_sleep() {
  i2c_start(I2C_ADDR_ATECC<<1);
  i2c_write("\x01", 1);
	if (_BERR)
		return false;
    //return i2c_wait(false);
	//smb_write( I2C_ADDR_ATECC508A, "\x01", 1);
}

bool atecc_wake() {
  uint8_t i = 0;
  uint8_t _400khz = I2CTL & _400KHZ;
  bool success;
  // hold SDA low for 60 us
  I2CTL &= ~_400KHZ;
  I2CS  = _START;
  I2DAT = 0x00;
  success = i2c_wait(/*need_ack=*/false);
  i2c_stop();
  I2CTL |= _400khz;
  return success;
}

bool atecc_send(atecc_io_t *packet)
{
  uint8_t* crc_dat = ((uint8_t *)packet)+1;
  crc16(packet->len-2, crc_dat, crc_dat+packet->len-2);
  if(!i2c_start(I2C_ADDR_ATECC<<1))
		goto fail;
  if(!i2c_write((uint8_t*)packet, packet->len+1))
		goto fail;
  if(!i2c_stop())
    return false;
	return true;
fail:
  i2c_stop();
  return false;
}

bool atecc_recv(atecc_io_t *packet, uint8_t rxsize) {
  if(!i2c_start((I2C_ADDR_ATECC<<1)|1))
		goto fail;
	if(!i2c_read(((uint8_t*)packet)+1/*TODO start from packet.txsize*/, rxsize))
		goto fail;
  // TODO: check CRC 
  return true;
fail:
  i2c_stop();
  return false;
}

static void atecc_delay(uint8_t opcode)
{
	uint8_t delay = 0;
	switch(opcode)
	{
    case ATECC_OP_NONCE:
      delay = 29;
		case ATECC_OP_SIGN:
			//delay = 60; // 508A
      delay = 115; // 608A
			break;
		case ATECC_OP_GENKEY:
			delay = 115;
			break;
		default:
			break;
	}
	delay_ms(delay);
}

bool atecc_send_recv(atecc_io_t *packet, uint8_t rxsize)
{
  if (!atecc_send(packet))
    return false;
	atecc_delay(packet->command.opcode);
  if (!atecc_recv(packet, rxsize))
    return false;
  return true;
}

bool atecc_nonce(atecc_io_t *packet, __xdata const uint8_t *nonce)
{
  packet->command.opcode = ATECC_OP_NONCE;
  packet->command.p1 = NONCE_MODE_PASSTHROUGH | NONCE_MODE_TARGET_TEMPKEY | NONCE_MODE_INPUT_LEN_32;
  packet->command.p2 = 0;
  xmemcpy((__xdata void *)packet->command.data, (__xdata void *)nonce, 32);
  packet->len = 39;

  if (!atecc_send_recv(packet, 4))
    return false;
  // if (packet->data[0] != 0)
  //   return false;

  return true;
}

bool atecc_sign(atecc_io_t *packet, uint16_t key_id, /*__xdata uint8_t **signature*/__xdata uint8_t *signature)
{
  packet->command.opcode = ATECC_OP_SIGN;
  packet->command.p1 = SIGN_MODE_EXTERNAL | SIGN_MODE_SOURCE_TEMPKEY;
  packet->command.p2 = key_id;
  packet->len = 7;

  if (!atecc_send_recv(packet, 67))
  {
    //return false;
  }
  // if (packet->data[0] != 0x67)
  //   return false;

  //*signature = &packet->data[1];
  /*i2c_start(I2C_ADDR_ATECC<<1);
  i2c_write((uint8_t*)packet->data, 64);
  i2c_stop();*/
  xmemcpy((__xdata void *)signature, (__xdata void *)packet->data, 64);
  return true;
}

void atecc_init(atecc_io_t *packet){
  __xdata const uint8_t nonce[32] = { 0 };
  __xdata uint8_t signature[64];

  atecc_wake();
  delay_us(1500);

  if(!atecc_nonce(packet, nonce))
    return;
  if(!atecc_sign(packet, 0, signature))
    return;
}
