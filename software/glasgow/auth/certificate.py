from binascii import unhexlify, hexlify

from . import signature_from_bytes

from enum import IntEnum

from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


class Signer(object):
    def __init__(self, signer_id: bytes):
        signer_id = bytes(signer_id)
        self.module_id = signer_id[0]
        self.ecc_id = signer_id[1] >> 4
        self.slot_id = signer_id[1] & 0x0F


class Validity(object):
    _NO_EXPIRY = datetime(2049, 12, 31, hour=23, minute=59, second=59)

    def __init__(self, not_valid_before, not_valid_after=None):
        assert(not_valid_before.minute == 0)
        assert(not_valid_before.second == 0)
        if not_valid_after is not None:
            assert(not_valid_after.minute == 0)
            assert(not_valid_after.second == 0)
        else:
            not_valid_after = self._NO_EXPIRY
        self.not_valid_before = not_valid_before
        self.not_valid_after = not_valid_after

    @classmethod
    def from_bytes(cls, enc_dates):
        year = (enc_dates[0] >> 3) + 2000
        month = ((enc_dates[0] & 0x07) << 1) | ((enc_dates[1] & 0x80) >> 7)
        day = (enc_dates[1] & 0x7C) >> 2
        hour = ((enc_dates[1] & 0x03) << 3) | ((enc_dates[2] & 0xE0) >> 5)
        expire_years = enc_dates[2] & 0x1F
        not_valid_before = datetime(year, month, day, hour)
        if expire_years:
            not_valid_after = datetime(year+expire_years, month, day, hour=hour)
        else:
            not_valid_after = None
        return cls(not_valid_before, not_valid_after)
    
    def __bytes__(self):
        year = self.not_valid_before.year - 2000
        assert(year in range(32))
        month = self.not_valid_before.month
        day = self.not_valid_before.day
        hour = self.not_valid_after.hour
        if self.not_valid_after is self._NO_EXPIRY:
            expire_years = 0
        else:
            expire_years = self.not_valid_after.year - self.not_valid_before.year
            assert(expire_years in range(1, 32))
        enc_dates = expire_years
        enc_dates |= year << 19
        enc_dates |= month << 15
        enc_dates |= day << 10
        enc_dates |= hour << 5
        return enc_dates.to_bytes(3, byteorder='big')

    def __eq__(self, other): 
        if not isinstance(other, Validity):
            # don't attempt to compare against unrelated types
            return NotImplemented

        return self.not_valid_before == other.not_valid_before and self.not_valid_after == other.not_valid_after


class SNSource(IntEnum):
    SERIAL_NUM     = 0x0
    SUBJECT_PUBKEY = 0xA
    DEVICE_SERIAL  = 0xB


class SerialNumber(object):

    def __init__(self, serial, sn_source):
        self.serial = serial
        self.source = sn_source

    def __bytes__(self):
        return bytes(self.serial)

    @classmethod
    def from_public_key(cls, pub_key, enc_dates):
        assert(isinstance(pub_key, ec.EllipticCurvePublicKey))
        pub_bytes = pub_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        pn = pub_key.public_numbers()
        p_bytes = lambda point: point.to_bytes(32, byteorder='big')
        pub_bytes = p_bytes(pn.x) + p_bytes(pn.y)
        pub_key = pub_bytes

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(pub_key)
        digest.update(enc_dates)
        cert_sn = bytearray(digest.finalize())
        cert_sn[0] &= 0x7F
        cert_sn[0] |= 0x40
        return cls(cert_sn[:16], SNSource.SUBJECT_PUBKEY)

    @classmethod
    def from_source(cls, sn_source: SNSource, pub_key=None, enc_dates=None):
        if sn_source is SNSource.SUBJECT_PUBKEY:
            return cls.from_public_key(pub_key, enc_dates)
        else:
            raise ValueError()


class Template(IntEnum):
    DEVICE = 0
    SIGNER = 1

class CompressedCertificateBuilder(x509.CertificateBuilder):
    VERSION_0 = 0
    CHAIN_ID = 0x0
    FORMAT_VERSION = 0x0

    def __init__(self, *args, signer_id=None, template_id=Template.SIGNER, chain_id=0, sn_source=SNSource.SUBJECT_PUBKEY, **kwargs):
        if signer_id is not None:
            raise ValueError()

        self._template_id = template_id
        self._chain_id = chain_id
        self._sn_source = sn_source
        self._format_version = self.VERSION_0
        super().__init__(**kwargs)
    
    @property
    def signer_id(self):
        if self._template_id is Template.DEVICE:
            common_name = self._issuer_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        elif self._template_id is Template.SIGNER:
            common_name = self._subject_name.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        return unhexlify(common_name.value)

    @classmethod
    def from_bytes(cls, compressed_cert, public_key, issuer_public_key, subject_name=None, issuer_name=None):
        compressed_cert = bytes(compressed_cert)
        # signature = signature_from_bytes(compressed_cert[:64])
        signature = encode_dss_signature(
            int.from_bytes(compressed_cert[:32], 'big'),
            int.from_bytes(compressed_cert[32:64], 'big')
        )
        enc_dates = compressed_cert[64:67]
        validity = Validity.from_bytes(enc_dates)
        signer_id = compressed_cert[67:69]
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, signer_id.hex().upper())
        ])
        template_id = Template(compressed_cert[69] >> 4)
        chain_id = compressed_cert[69] & 0x0F
        sn_source = compressed_cert[70] >> 4
        assert(compressed_cert[70] & 0x0F == 0) # version 0
        reserved = compressed_cert[71]

        # serial_number = x509.random_serial_number()
        serial_number = SerialNumber.from_source(SNSource(sn_source), public_key, enc_dates)

        cert = (
            cls()
            .public_key(public_key)
            .serial_number(int.from_bytes(bytes(serial_number), byteorder='big'))
            .not_valid_before(validity.not_valid_before)
            .not_valid_after(validity.not_valid_after)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_public_key), False
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key), False
            )
            #.sign(key, hashes.SHA256(), default_backend())
        )
        if template_id is Template.DEVICE:
            cert = cert.issuer_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, signer_id.hex().upper())
            ]))
            # see https://github.com/MicrochipTech/cryptoauthlib/issues/153
            if subject_name:
                cert = cert.subject_name(subject_name)
        elif template_id is Template.SIGNER:
            cert = cert.subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, signer_id.hex().upper())
            ]))
            # order of extensions is important but is not specified
            cert = cert.add_extension(
                x509.BasicConstraints(ca=True, path_length=1), False
            )
            # see https://github.com/MicrochipTech/cryptoauthlib/issues/153
            if issuer_name:
                cert = cert.issuer_name(issuer_name)

        # workaround, there is no API to set an existing signature
        dummy_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        cert = cert.sign(dummy_key, hashes.SHA256(), default_backend())
        cert_der = cert.public_bytes(encoding=serialization.Encoding.DER)

        assert(cert.signature in cert_der)

        # see 3.2 Signature Reconstruction in Compressed Certificate Definition
        sig_offset = cert_der.find(cert.signature)  
        cert_der = bytearray(cert_der[:sig_offset] + signature)
        cert_der[2:4] = (len(cert_der) - 4).to_bytes(2, 'big')
        cert_der[sig_offset-2] = len(signature) + 1
        cert = x509.load_der_x509_certificate(cert_der)

        return cert
    
    def sign_compressed(self, private_key, backend):
        cert = self.sign(private_key, hashes.SHA256(), backend)
        compressed_cert = bytearray(72)
        r, s = decode_dss_signature(cert.signature)

        compressed_cert[:32] = r.to_bytes(32, 'big')
        compressed_cert[32:64] = s.to_bytes(32, 'big')
        compressed_cert[64:67] = bytes(Validity(cert.not_valid_before, cert.not_valid_after))
        common_name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0]
        compressed_cert[67:69] = unhexlify(common_name.value)
        compressed_cert[67:69] = self.signer_id
        compressed_cert[69] = self._template_id << 4 | self._chain_id
        compressed_cert[70] = SNSource.SUBJECT_PUBKEY << 4

        return compressed_cert


import unittest


class CertificateTestCase(unittest.TestCase):

    def setUp(self):
        x, y = (
            int('961dc17cd422c282c93ada0e2e0bbcba34e07d3b29859c90dec7a8f576897f06', 16),
            int('f89efa29a1a8ef39e003f97520c768015dc27b1fba755dad558ca3975aaa592d', 16)
        )
        point = ec.EllipticCurvePublicNumbers(x,y, ec.SECP256R1())
        self.device_pubkey = point.public_key(default_backend())

        self.root_key = ec.derive_private_key(
            0xaabbccdd,
            ec.SECP256R1(),
            backend=default_backend()
        )
        self.signer_key = ec.derive_private_key(
            0xff00ff00,
            ec.SECP256R1(),
            backend=default_backend()
        )

    def test_signer_cert(self):
        root_key = self.root_key
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "GlasgowCA")
        ])

        signer_key = self.signer_key
        signer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CCCC") # TODO: fix SSSS
        ])
        # path_len=0 means this cert can only sign itself, not other certs.
        basic_constraints = x509.BasicConstraints(ca=True, path_length=4)
        valid_from = datetime(2021, 1, 1)
        signer_validity = Validity(valid_from, valid_from.replace(year=2030))
        signer_serial_number = SerialNumber.from_source(SNSource.SUBJECT_PUBKEY, signer_key.public_key(), bytes(signer_validity))

        signer_cert_builder = CompressedCertificateBuilder(
            template_id=Template.SIGNER,
            issuer_name=root_name,
            subject_name=signer_name,
            public_key=signer_key.public_key(),
            serial_number=int.from_bytes(signer_serial_number, byteorder='big'),
            not_valid_before=signer_validity.not_valid_before,
            not_valid_after=signer_validity.not_valid_after,
            extensions=[
                x509.Extension(x509.AuthorityKeyIdentifier.oid, False, x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key())),
                x509.Extension(x509.SubjectKeyIdentifier.oid, False, x509.SubjectKeyIdentifier.from_public_key(signer_key.public_key())),
                x509.Extension(x509.BasicConstraints.oid, False, x509.BasicConstraints(ca=True, path_length=1)),
            ]
        )

        signer_cert = signer_cert_builder.sign(root_key, hashes.SHA256(), default_backend())
        signer_compressed_cert = signer_cert_builder.sign_compressed(root_key, default_backend())
        signer_reconstructed_cert = CompressedCertificateBuilder.from_bytes(signer_compressed_cert, signer_key.public_key(), root_key.public_key(), issuer_name=root_name)

        signer_pem = signer_reconstructed_cert.public_bytes(encoding=serialization.Encoding.PEM)
        with open("signer.pem", "wb") as f:
            f.write(signer_pem)
        
        signer_cert = x509.load_pem_x509_certificate(signer_pem)
        self.root_key.public_key().verify(
            signer_cert.signature,
            signer_cert.tbs_certificate_bytes,
            ec.ECDSA(signer_cert.signature_hash_algorithm),
        )

    def test_device_cert(self):
        root_key = self.root_key
        root_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "GlasgowCA")
        ])

        signer_key = self.signer_key
        signer_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "CCCC")
        ])
        # path_len=0 means this cert can only sign itself, not other certs.
        basic_constraints = x509.BasicConstraints(ca=True, path_length=1)
        valid_from = datetime(2021, 1, 1)
        signer_cert = (
            x509.CertificateBuilder()
            .subject_name(signer_name)
            .issuer_name(root_name)
            .public_key(signer_key.public_key())
            .serial_number(1000)
            .not_valid_before(valid_from)
            .not_valid_after(valid_from.replace(year=2030))
            .add_extension(basic_constraints, False)
            .sign(root_key, hashes.SHA256(), default_backend())
        )

        device_name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "DDDD")
        ])
        device_validity = Validity(valid_from, valid_from.replace(year=2030))
        device_serial_number = SerialNumber.from_source(SNSource.SUBJECT_PUBKEY, self.device_pubkey, bytes(device_validity))

        device_cert_builder = CompressedCertificateBuilder(
            template_id=Template.DEVICE,
            issuer_name=signer_name,
            subject_name=device_name,
            public_key=self.device_pubkey,
            serial_number=int.from_bytes(device_serial_number, byteorder='big'),
            not_valid_before=device_validity.not_valid_before,
            not_valid_after=device_validity.not_valid_after,
            # see https://github.com/alex/x509-validator/issues/12 for validator
            extensions=[
                x509.Extension(x509.AuthorityKeyIdentifier.oid, False, x509.AuthorityKeyIdentifier.from_issuer_public_key(signer_key.public_key())),
                x509.Extension(x509.SubjectKeyIdentifier.oid, False, x509.SubjectKeyIdentifier.from_public_key(self.device_pubkey)),
            ]
        )

        device_cert = device_cert_builder.sign(signer_key, hashes.SHA256(), default_backend())
        device_compressed_cert = device_cert_builder.sign_compressed(signer_key, default_backend())
        device_reconstructed_cert = CompressedCertificateBuilder.from_bytes(device_compressed_cert, self.device_pubkey, signer_key.public_key(), subject_name=device_name)

        device_pem = device_reconstructed_cert.public_bytes(encoding=serialization.Encoding.PEM)
        with open("device_reconstructed.pem", "wb") as f:
            f.write(device_pem)

        device_cert = x509.load_pem_x509_certificate(device_pem)
        signer_key.public_key().verify(
            device_cert.signature,
            device_cert.tbs_certificate_bytes,
            ec.ECDSA(device_cert.signature_hash_algorithm),
        )

    def test_validity(self):
        not_valid_before = datetime(2019, 1, 1)
        not_valid_after = datetime(2030, 1, 1)
        validity = Validity(not_valid_before, not_valid_after)
        self.assertEqual(validity, Validity.from_bytes(bytes(validity)))
