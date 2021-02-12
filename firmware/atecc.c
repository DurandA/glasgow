#include <fx2lib.h>
#include <fx2delay.h>
#include <fx2regs.h>
#include <fx2i2c.h>
#include "glasgow.h"

enum {
  ATECC_OP_READ   = 0x02,
  ATECC_OP_NONCE   = 0x16,
  ATECC_OP_SIGN  = 0x41,
  ATECC_OP_GENKEY = 0x40,
};

uint16_t crc16(__xdata const uint8_t *data, uint8_t len)
{
  uint16_t crc = 0;
  uint16_t polynom = 0x8005;
  uint8_t shift_register;
  uint8_t data_bit, crc_bit;
  uint8_t i;

  for (i = 0; i < len; i++)
  {
    for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1)
    {
      data_bit = (data[i] & shift_register) ? 1 : 0;
      crc_bit = crc >> 15;
      crc <<= 1;
      if (data_bit != crc_bit)
      {
        crc ^= polynom;
      }
    }
  }
  return crc;
}

bool atecc_idle() {
  i2c_start((uint8_t)I2C_ADDR_ATECC<<1);
  if(!i2c_write("\x02", 1))
    goto fail;
  if(!i2c_stop())
    return false;
  return true;

fail:
  i2c_stop();
  return false;
}

bool atecc_sleep() {
  i2c_start((uint8_t)I2C_ADDR_ATECC<<1);
  if(!i2c_write("\x01", 1))
    goto fail;
  if(!i2c_stop())
    return false;
  return true;

fail:
  i2c_stop();
  return false;
}

bool atecc_wake() {
  uint8_t i = 0;
  uint8_t _400khz = I2CTL & _400KHZ;
  bool success;
  // hold SDA low for 60us
  I2CTL &= ~_400KHZ;
  I2CS  = _START;
  I2DAT = 0x00;
  success = i2c_wait(/*need_ack=*/false);
  i2c_stop();
  I2CTL |= _400khz;
  return success;
}

bool atecc_send(atecc_io_t *io_buf)
{
  __xdata uint8_t* crc_dat = ((__xdata uint8_t *)io_buf)+1;
  __xdata uint16_t* crc = (uint16_t*)(crc_dat+io_buf->len-2);
  *crc = crc16(crc_dat, io_buf->len-2);
  if(!i2c_start(I2C_ADDR_ATECC<<1))
		goto fail;
  if(!i2c_write((__xdata uint8_t*)io_buf, io_buf->len+1))
		goto fail;
  if(!i2c_stop())
    return false;
	return true;
fail:
  i2c_stop();
  return false;
}

bool atecc_recv(atecc_io_t *io_buf, uint8_t len) {
  if(!i2c_start((I2C_ADDR_ATECC<<1)|1))
		goto fail;
	if(!i2c_read(((__xdata uint8_t*)io_buf)+1/*TODO start from io_buf.len*/, len))
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
    case ATECC_OP_READ:
      delay = 5;
      break;
    case ATECC_OP_NONCE:
      delay = 29;
      break;
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

bool atecc_send_recv(atecc_io_t *io_buf, uint8_t rxlen)
{
  if (!atecc_send(io_buf))
    return false;
	atecc_delay(io_buf->command.opcode);
  if (!atecc_recv(io_buf, rxlen))
    return false;
  return true;
}

bool atecc_read_data(atecc_io_t *io_buf, uint8_t slot, uint8_t block, __xdata uint8_t *data)
{
  io_buf->command.opcode = ATECC_OP_READ;
  io_buf->command.p1 = ZONE_DATA | ZONE_READWRITE_32;
  io_buf->command.p2 = (uint16_t)block << 8 | slot << 3;
  io_buf->len = 7;

  if (!atecc_send_recv(io_buf, 35))
    return false;

  xmemcpy((__xdata void *)data, (__xdata void *)io_buf->data, 32);
  return true;
}

bool atecc_nonce(atecc_io_t *io_buf, __xdata const uint8_t *nonce)
{
  io_buf->command.opcode = ATECC_OP_NONCE;
  io_buf->command.p1 = NONCE_MODE_PASSTHROUGH | NONCE_MODE_TARGET_TEMPKEY | NONCE_MODE_INPUT_LEN_32;
  io_buf->command.p2 = 0;
  io_buf->len = 39;
  xmemcpy((__xdata void *)io_buf->command.data, (__xdata void *)nonce, 32);

  if (!atecc_send_recv(io_buf, 4))
    return false;
  if (io_buf->status != 0)
    return false;

  return true;
}

bool atecc_sign(atecc_io_t *io_buf, uint16_t key_id, __xdata uint8_t *signature)
{
  io_buf->command.opcode = ATECC_OP_SIGN;
  io_buf->command.p1 = SIGN_MODE_EXTERNAL | SIGN_MODE_SOURCE_TEMPKEY;
  io_buf->command.p2 = key_id;
  io_buf->len = 7;

  if (!atecc_send_recv(io_buf, 67))
    return false;

  xmemcpy((__xdata void *)signature, (__xdata void *)io_buf->data, 64);
  return true;
}

void atecc_init(atecc_io_t *io_buf){
  __xdata const uint8_t nonce[32] = { 0 };
  __xdata uint8_t signature[64];

  atecc_wake();
  delay_us(1500);

  if(!atecc_nonce(io_buf, nonce))
    return;
  if(!atecc_sign(io_buf, 0, signature))
    return;
}
