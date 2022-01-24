from asgiref.sync import async_to_sync, sync_to_async
import jwcrypto.jwk
import json
from pprint import pprint
from typing import List, Optional

from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID, DID_URL, VerificationMaterial, VerificationMaterialFormat, VerificationMethodType
from didcomm.did_doc.did_doc import DIDCommService, DIDDoc, VerificationMethod
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.message import Message
from didcomm.pack_encrypted import PackEncryptedConfig, pack_encrypted
from didcomm.pack_signed import pack_signed
from didcomm.secrets.secrets_resolver import Secret, SecretsResolver
from didcomm.unpack import unpack

import os

os.environ.setdefault('DJANGO_FERNET_KEY', 'z597rAprVvMSXcKfVqOUCj556LYNiQJWfjVC14WFQ5d9bfNnwT')
os.environ.setdefault('DJANGO_SECRET_KEY', 'django-insecure-kr5_(8vjoc0-e$-@zm9axua_j2f3_qai2oqm__tfwsz)!m_v@i')
os.environ.setdefault('DJANGO_SETTINGS', 'dev')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
import django
django.setup()
from trustapi.didweb.models import SigningKey


# https://github.com/pyca/cryptography/issues/5557#issuecomment-739339132
def ed25519_to_x25519(key: jwcrypto.jwk.JWK) -> jwcrypto.jwk.JWK:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends.openssl import backend
    from jwcrypto.common import base64url_decode

    hasher = hashes.Hash(hashes.SHA512())
    hasher.update(base64url_decode(key['d']))
    h = bytearray(hasher.finalize())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64

    xpk0 = backend.x25519_load_private_bytes(h[0:32])

    return jwcrypto.jwk.JWK.from_pyca(xpk0)


def key_to_doc(key: SigningKey) -> DIDDoc:
    did_doc = key.generate_did_document()
    edKey = key.jwk_private_key
    xKey = ed25519_to_x25519(edKey)

    vms = [
        VerificationMethod(
            id=did_doc['verificationMethod'][0]['id'],
            controller=did_doc['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json.dumps(did_doc['verificationMethod'][0]['publicKeyJwk'])
            )
        ),
        VerificationMethod(
            id=f"{key.did}#X25519",
            controller=did_doc['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=json.dumps(xKey.export(private_key=False, as_dict=True))
            )
        )
    ]

    return DIDDoc(
        did=did_doc['id'],
        authentication_kids=[
            vms[0].id,
        ],
        key_agreement_kids=[
            vms[1].id
        ],
        verification_methods=vms,
        didcomm_services=[
            DIDCommService(
                id=x['id'],
                service_endpoint=x['serviceEndpoint'],
                accept=[],
                routing_keys=[]
            ) for x in did_doc['service']
        ]
    )


def key_to_secrets(key: SigningKey) -> List[Secret]:
    did_doc = key.generate_did_document()
    edKey = json.dumps(key.jwk_private_key.export(as_dict=True))
    xKey = json.dumps(ed25519_to_x25519(key.jwk_private_key).export(as_dict=True))
    return [
        Secret(
            kid=did_doc['verificationMethod'][0]['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=edKey
            )
        ),
        Secret(
            kid=f"{key.did}#X25519",
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=xKey
            )
        )
    ]


class DotMedDIDResolver(DIDResolver):
    def __init__(self):
        super()

    async def resolve(self, did: DID) -> Optional[DIDDoc]:
        signing_key = await sync_to_async(SigningKey.objects.get)(did=did)
        if not signing_key:
            return None
        return key_to_doc(signing_key)


class DotMedSecretsResolver(SecretsResolver):
    def __init__(self):
        super()

    async def get_key(self, kid: DID_URL) -> Optional[Secret]:
        # TODO: extract '#' stripping
        signing_key = await sync_to_async(SigningKey.objects.get)(did=kid.split('#')[0])
        secrets = key_to_secrets(signing_key)
        for secret in secrets:
            if secret.kid == kid:
                return secret

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        # TODO: extract '#' stripping
        @sync_to_async
        def _get_keys():
            return list(SigningKey.objects.filter(did__in=[kid.split('#')[0] for kid in kids]))
        signing_keys = await _get_keys()
        secrets = [elem for sublist in [key_to_secrets(x) for x in signing_keys] for elem in sublist]
        keys = []
        for secret in secrets:
            if secret.kid in kids:
                keys.append(secret.kid)
        return keys


resolver = ResolversConfig(DotMedSecretsResolver(), DotMedDIDResolver())

sk0: SigningKey = SigningKey.objects.all()[0]
sk1: SigningKey = SigningKey.objects.all()[1]

message = Message(
    id="1234567890",
    frm=sk0.did,
    to=[sk1.did],
    type="application/testing",
    created_time=1516269022,
    expires_time=1516385931,
    body={
        "aaa": 1,
        "bbb": 2
    }
)

pack_result = async_to_sync(pack_encrypted)(
    resolvers_config=resolver,
    message=message,
    frm=sk0.did,
    to=sk1.did,
    pack_config=PackEncryptedConfig()
)

packed_msg = pack_result.packed_msg
pprint(json.loads(packed_msg))
print(110)

unpack_result = async_to_sync(unpack)(resolver, packed_msg)
unpacked_msg: Message = unpack_result.message
unpacked_msg.as_dict()
pprint(unpacked_msg)
print(120)

print(f"Messages are equal: '{message == unpack_result.message}'")
