# -*- coding: utf-8 -*-
import OpenSSL
from xades.constants import MAP_HASHLIB
from xades.policy import ETSI, DS
from xmlsig.utils import create_node
from xades.ns import EtsiNS
from xmlsig.utils import get_rdns_name
from base64 import b64encode
from datetime import datetime
from lxml import etree
import xmlsig
from xades import ObjectIdentifier, XAdESContext, template, utils
from xades.policy import GenericPolicyId
from cryptography.hazmat.primitives.serialization import pkcs12
import pathlib


class MiGenericPolicyId(GenericPolicyId):
    """
    Sobreescrito para cambiar: 'self.hash_method' por 'xmlsig.constants.TransformSha512'
    """
    def calculate_certificate(self, node, key_x509):
        fingerprint = key_x509.fingerprint(MAP_HASHLIB[xmlsig.constants.TransformSha512]())
        _ETSI_Cert = ETSI.Cert(
            ETSI.CertDigest(
                DS.DigestMethod(Algorithm=xmlsig.constants.TransformSha512),
                DS.DigestValue(b64encode(fingerprint).decode()),
            ),
            ETSI.IssuerSerial(
                DS.X509IssuerName(get_rdns_name(key_x509.issuer.rdns)),
                DS.X509SerialNumber(str(key_x509.serial_number)),
            ),
        )
        node.append(_ETSI_Cert)

    def _resolve_policy(self, identifier):
        """
        Sobreescrito porque da error la url
        """
        path_base = pathlib.Path(__file__).parent.resolve()
        nom_pdf = identifier.split('/')[-1]
        polica_firma = os.path.join(path_base, nom_pdf)
        with open(polica_firma, 'rb') as f:
            return f.read()


class MiXAdESContext(XAdESContext):
    """
    Sobreesctito para añadir los 'ca_certificates'
    """
    def load_pkcs12(self, key):
        if isinstance(key, OpenSSL.crypto.PKCS12):
            # This would happen if we are using pyOpenSSL
            self.x509 = key.get_certificate().to_cryptography()
            self.public_key = key.get_certificate().to_cryptography().public_key()
            self.private_key = key.get_privatekey().to_cryptography_key()
            self.ca_certificates = key.get_ca_certificates()
        elif isinstance(key, pkcs12.PKCS12KeyAndCertificates):
            # This would happen if we are using cryptography
            # cuando se lee con load_pkcs12
            self.x509 = key.cert.certificate
            self.public_key = key.cert.certificate.public_key()
            self.private_key = key.key
            for cer in key.additional_certs:
                self.ca_certificates.append(cer.certificate)
        elif isinstance(key, tuple):
            # This would happen if we are using cryptography
            # cuando se lee con load_key_and_certificates
            private_key, certificate, ca_certificates = key
            self.x509 = certificate
            self.public_key = certificate.public_key()
            self.private_key = private_key
            self.ca_certificates = ca_certificates
        else:
            raise NotImplementedError()


class MiObjectIdentifier(ObjectIdentifier):

    def to_xml(self, node):
        """
        Sobreescrito para añadir el atributo: 'Qualifier="OIDAsURN"'
        """
        n = create_node('Identifier', node, EtsiNS, text=self.identifier)
        n.set('Qualifier', 'OIDAsURN')
        if self.description is not None:
            create_node('Description', node, EtsiNS).text = self.description
        if len(self.references) > 0:
            documentation = create_node('DocumentationReferences', node, EtsiNS)
            for reference in self.references:
                create_node(
                    'DocumentationReference', documentation, EtsiNS
                ).text = reference


def firma(certificado, origen, verify=True):
    root = etree.parse(origen).getroot()

    signature_id = utils.get_unique_id()
    reference_id = utils.get_unique_id()

    signature = xmlsig.template.create(
        xmlsig.constants.TransformInclC14N,
        xmlsig.constants.TransformRsaSha512,
        f'Signature-{signature_id}-Signature',
    )
    ref = xmlsig.template.add_reference(
        signature,
        xmlsig.constants.TransformSha512,
        uri='',
        name=f'Reference-{reference_id}'
    )
    xmlsig.template.add_transform(ref, xmlsig.constants.TransformEnveloped)

    xmlsig.template.add_reference(
        signature,
        xmlsig.constants.TransformSha512,
        uri=f'#Signature-{signature_id}-SignedProperties',
        uri_type='http://uri.etsi.org/01903#SignedProperties'
    )
    xmlsig.template.add_reference(
        signature, xmlsig.constants.TransformSha512,
        uri=f'#Signature-{signature_id}-KeyInfo'
    )
    ki = xmlsig.template.ensure_key_info(
        signature,
        name=f'Signature-{signature_id}-KeyInfo'
    )
    data = xmlsig.template.add_x509_data(ki)
    xmlsig.template.x509_data_add_certificate(data)
    xmlsig.template.add_key_value(ki)

    qualifying = template.create_qualifying_properties(
        signature,
        etsi='xades',
        name=f'Signature-{signature_id}-QualifyingProperties'
    )
    #utils.ensure_id(qualifying)

    props = template.create_signed_properties(
        qualifying,
        datetime=datetime.now(),
        name=f'Signature-{signature_id}-SignedProperties'
    )
    template.add_claimed_role(props, 'emisor')
    signed_do = template.ensure_signed_data_object_properties(props)
    template.add_data_object_format(
        signed_do,
        reference=f'#Reference-{reference_id}',
        identifier=MiObjectIdentifier('urn:oid:1.2.840.10003.5.109.10', ''),
        mime_type='text/xml',
        encoding='',
        description=''
    )

    root.append(signature)

    policy = MiGenericPolicyId(
        'http://www.facturae.es/politica_de_firma_formato_facturae/politica_de_firma_formato_facturae_v3_1.pdf',
        '',
        xmlsig.constants.TransformSha1,
    )

    ctx = MiXAdESContext(policy)
    ctx.load_pkcs12(certificado)
    ctx.sign(signature)
    if verify:
        ctx.verify(signature)

    return etree.tostring(root, encoding='UTF-8', xml_declaration=True, standalone=False)


if __name__ == '__main__':
    import sys
    import os
    import argparse
    from io import StringIO, BytesIO
    from cryptography.hazmat.primitives.serialization import pkcs12
    import codecs

    __version__ = '0.0.1'

    parser = argparse.ArgumentParser(description='Firma XML Facturae v3.2.x XAdES (Por Juhegue)')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-o', '--origen', dest='origen', type=str, help='XML origen', required=True)
    parser.add_argument('-c', '--certificado', dest='certificado', type=str, help='Certidicado pkcs12', required=True)
    parser.add_argument('-p', '--clave', dest='clave', type=str, help='Clave certificado', required=True)
    parser.add_argument('-x', '--validar', dest='validar', type=str, help='Validar version', required=False,
                        choices=['3.2', '3.2.1', '3.2.2', 'null'], default='3.2')
    args = parser.parse_args()

    class FirmaError(Exception):
        ...

    try:
        try:
            with open(args.certificado, 'rb') as f:
                data = f.read()
                # certificado = OpenSSL.crypto.load_pkcs12(data, args.clave.encode())
                # certificado = pkcs12.load_pkcs12(data, args.clave.encode())
                certificado = pkcs12.load_key_and_certificates(data, args.clave.encode())
        except Exception as e:
            raise FirmaError(f'ERROR certificado [{e.__class__.__name__}]. {e}')

        try:
            root = etree.parse(args.origen)
            xml = etree.tostring(root, encoding='UTF-8', xml_declaration=False).decode('utf8')
        except Exception as e:
            raise FirmaError(f'ERROR XML [{e.__class__.__name__}]. {e}')
        
        try:
            verify = False if args.validar == 'null' else True
            xsig = firma(certificado, StringIO(xml), verify).decode()
        except Exception as e:
            raise FirmaError(f'ERROR Firma [{e.__class__.__name__}]. {e}')

        if args.validar != 'null':
            try:
                version = args.validar.replace('.', '_')
                path = os.path.join(os.path.dirname(__file__))
                xsd = os.path.join(path, f'Facturaev{version}.xml')
                with codecs.open(xsd, 'r', 'utf-8') as f:
                    xsd_data = f.read()
                xsd_shema = os.path.join(path, 'xmldsig-core-schema.xsd')
                xsd_shema = 'file:///' + xsd_shema.replace('\\', '/')
                xsd_data = xsd_data.replace('http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd', xsd_shema)
                xsd_tree = etree.fromstring(xsd_data)
                xml_tree = etree.parse(BytesIO(xsig.encode('utf-8')))
                schema = etree.XMLSchema(xsd_tree)
                schema.assertValid(xml_tree)
            except etree.DocumentInvalid:
                errors = list()
                for error in schema.error_log:
                    errors.append(f'(Line {error.line}) {error.message}')
                err = '. '.join(errors)
                raise FirmaError(f'ERROR al validar: {err}')

            except Exception as e:
                raise FirmaError(f'ERROR validar [{e.__class__.__name__}]. {e}')

        pathname, _ = os.path.splitext(args.origen)
        try:
            with codecs.open(f'{pathname}.xsig', 'w', 'utf-8') as f:
                f.write(xsig)
        except Exception as e:
            raise FirmaError(f'ERROR grabar [{e.__class__.__name__}]. {e}')

    except FirmaError as e:
        print(e)
        sys.exit(1)
