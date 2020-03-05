import usb1
import asyncio
import os
from ..device.hardware import GlasgowHardwareDevice

from ecdsa import NIST256p, VerifyingKey
from ecdsa.ellipticcurve import Point as ECDSA_Point
from binascii import hexlify, unhexlify

x, y = (
    int('4addc7fb8998e8d9864d96a8899bab108ba47abe9087de214ded324a47fd87df', 16),
    int('4c83f25c2a1923e6b0b7a65e618af72215f4b0b042454755ef738f26186d192f', 16)
)
point = ECDSA_Point(NIST256p.curve, x, y)
vk = VerifyingKey.from_public_point(point, curve=NIST256p)

REQ_ATECC_SIGN   = 0x20
REQ_ATECC_CERT   = 0x21

async def main(loop):
    device = GlasgowHardwareDevice()
    cert = await device.control_read(usb1.REQUEST_TYPE_VENDOR, REQ_ATECC_CERT, 0, 0, 32)
    challenge = os.urandom(32)
    await device.control_write(usb1.REQUEST_TYPE_VENDOR, REQ_ATECC_SIGN, 0, 0, challenge)
    signature = await device.control_read(usb1.REQUEST_TYPE_VENDOR, REQ_ATECC_SIGN, 0, 0, 64)
    vk.verify_digest(signature, challenge)

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main(loop))
