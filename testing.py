import asyncio
from asyncio.events import get_event_loop
from pprint import pprint
from typing import Iterable, List, Optional

from attr import s
from didcomm.common.algorithms import AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import DID, DID_URL, VerificationMaterial, VerificationMaterialFormat, VerificationMethodType
from didcomm.did_doc.did_resolver import DIDResolver
from didcomm.did_doc.did_resolver_in_memory import DIDResolverInMemory
from didcomm.message import Message
from didcomm.pack_encrypted import PackEncryptedConfig, pack_encrypted
from didcomm.secrets.secrets_resolver import Secret, SecretsResolver
from didcomm.unpack import unpack
from tests.test_vectors.did_doc.mock_did_resolver import MockDIDResolverAllInSecrets, MockDIDResolverWithNonSecrets

from tests.test_vectors.secrets import (
    MockSecretsResolverAlice,
    MockSecretsResolverBob,
    MockSecretsResolverCharlie,
    MockSecretsResolverMediator1,
    MockSecretsResolverMediator2,
)
from tests.demo import test_demo, test_demo_attachments

import json

import os

from tests.test_vectors.secrets.mock_secrets_resolver import MockSecretsResolverInMemory
os.environ.setdefault('DJANGO_FERNET_KEY', 'z597rAprVvMSXcKfVqOUCj556LYNiQJWfjVC14WFQ5d9bfNnwT')
os.environ.setdefault('DJANGO_SECRET_KEY', 'django-insecure-kr5_(8vjoc0-e$-@zm9axua_j2f3_qai2oqm__tfwsz)!m_v@i')
os.environ.setdefault('DJANGO_SETTINGS', 'dev')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
import django
django.setup()
from trustapi.didweb.models import SigningKey, SigningKeyType

secrets_resolver_alice = MockSecretsResolverAlice()
secrets_resolver_bob = MockSecretsResolverBob()
secrets_resolver_charlie = MockSecretsResolverCharlie()
secrets_resolver_mediator1 = MockSecretsResolverMediator1()
secrets_resolver_mediator2 = MockSecretsResolverMediator2()

did_resolver_all_in_secrets = MockDIDResolverWithNonSecrets()

resolvers_config_alice = ResolversConfig(secrets_resolver_alice, did_resolver_all_in_secrets)
resolvers_config_bob = ResolversConfig(secrets_resolver_bob, did_resolver_all_in_secrets)
resolvers_config_charlie = ResolversConfig(secrets_resolver_charlie, did_resolver_all_in_secrets)
resolvers_config_mediator1 = ResolversConfig(secrets_resolver_mediator1, did_resolver_all_in_secrets)
resolvers_config_mediator2 = ResolversConfig(secrets_resolver_mediator2, did_resolver_all_in_secrets)

async def main_async():
    # await test_demo.test_demo_repudiable_authenticated_encryption(
    #     resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
    # )
    # await test_demo.test_demo_repudiable_non_authenticated_encryption(
    #     resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
    # )

    await test_demo_attachments.test_demo_attachments(
        resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
    )

# asyncio.run(main())


def async_to_sync_mine(func):
    from asyncio import get_event_loop
    def inner(*args, **kwargs):
        value = get_event_loop().run_until_complete(func(*args, **kwargs))
        return value
    return inner


@async_to_sync_mine
async def main_test():
    await test_demo.test_demo_repudiable_authenticated_encryption(
        resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
    )
    return 234

def tester():
    __ = test_demo.test_demo_repudiable_authenticated_encryption
    test_demo.test_demo_repudiable_authenticated_encryption = async_to_sync_mine(test_demo.test_demo_repudiable_authenticated_encryption)
    test_demo.test_demo_repudiable_authenticated_encryption(
        resolvers_config_alice, resolvers_config_bob, resolvers_config_mediator1
    )
    test_demo.test_demo_repudiable_authenticated_encryption = __
    return 983

# value = tester() # main_test()
# print(value)

a = SigningKey.objects.all()
b: SigningKey = a[0]
c = b.generate_did_document()
d = json.dumps(c, indent=4)
print(d)
_ = '''{
    "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://w3id.org/security/suites/ed25519-2020/v1"
    ],
    "id": "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med",
    "verificationMethod": [
        {
            "id": "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g",
            "publicKeyJwk": {
                "crv": "Ed25519",
                "kid": "la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g",
                "kty": "OKP",
                "x": "VynDwTIBa6zEmkjs7GnHyBShas-4l8Uo8G1SdD1pix4"
            }
        }
    ],
    "assertionMethod": [
        "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g"
    ],
    "authentication": [
        "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g"
    ],
    "service": [
        {
            "id": "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#didcomm",
            "type": "didcomm",
            "serviceEndpoint": "https://api.med/api/v1/inbox"
        }
    ]
}'''

from didcomm.did_doc.did_doc import DIDCommService, DIDDoc, VerificationMethod

import jwcrypto
k = jwcrypto.jwk.JWK.from_pem(b.public_key.encode())
j = b.jwk_public_key.key_type
jwk_obj = json.loads(b.jwk_public_key.export())

# key_curve:'Ed25519'
# key_id:'la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g'
# key_type:'OKP'

# dd = DIDDoc(
#     did=b.did,
#     key_agreement_kids=[
#         "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g"
#     ],
#     authentication_kids=[
#         "did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g"
#     ],
#     verification_methods=[
#         VerificationMethod(
#             id="did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g",
#             controller="did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med",
#             type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
#             verification_material=VerificationMaterial(
#                 format=VerificationMaterialFormat.JWK,
#                 value=json.loads(b.jwk_public_key.export())
#             )
#         )
#     ],
#     didcomm_services=[
#         DIDCommService(
#             id="did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#didcomm",
#             service_endpoint="https://api.med/api/v1/inbox",
#             accept=[],
#             routing_keys=[]
#         )
#     ]
# )

from asgiref.sync import async_to_sync, sync_to_async

def handle_key(puk: dict) -> dict:
    #if puk['crv'].lower() == 'ed25519':
    #    puk['crv'] = 'X25519'
    return puk

def key_to_doc(key: SigningKey) -> DIDDoc:

    did_doc = key.generate_did_document()

    _prek: jwcrypto.jwk.JWK = key._prek

    vms = [
        VerificationMethod(
            id=did_doc['verificationMethod'][0]['id'],
            controller=did_doc['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,  # TODO: Support for more formats
                value=json.dumps(handle_key(did_doc['verificationMethod'][0]['publicKeyJwk']))
            )
        ),
        VerificationMethod(
            id=f"{key.did}#X25519", #{_prek.thumbprint()}",
            controller=did_doc['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,  # TODO: Support for more formats
                value=json.dumps(handle_key(_prek.export(as_dict=True)))
            )
        )
    ]

    return DIDDoc(
        did=did_doc['id'],
        authentication_kids=[
            did_doc['verificationMethod'][0]['id'],
            # f"{key.did}#X25519" # #{_prek.thumbprint()}"
            # x if type(x) == str else x['id'] for x in did_doc['authentication']
        ],
        key_agreement_kids=[
            # did_doc['verificationMethod'][0]['id'],
            f"{key.did}#X25519" # #{_prek.thumbprint()}"
            # x['id'] for x in did_doc['verificationMethod']
        ],  # Blank for now, eventually iterate through 'keyAgreement' (pull from verificationmethod?)
        # TODO: Add lookup ability
        verification_methods=vms,
        # verification_methods=[
        #     VerificationMethod(
        #         id=x['id'],
        #         controller=did_doc['id'],
        #         type=VerificationMethodType.JSON_WEB_KEY_2020,  # TODO: Add support for more types
        #         verification_material=VerificationMaterial(
        #             format=VerificationMaterialFormat.JWK,  # TODO: Support for more formats
        #             value=json.dumps(handle_key(x['publicKeyJwk']))
        #         )
        #     ) for x in did_doc['verificationMethod']
        # ],
        didcomm_services=[
            DIDCommService(
                id=x['id'],
                service_endpoint=x['serviceEndpoint'],
                accept=[],
                routing_keys=[]
            ) for x in did_doc['service']
        ]
    )

def key_to_secrets(key: SigningKey) -> Secret:
    did_doc = key.generate_did_document()
    prk0 = json.dumps(handle_key(key.jwk_private_key.export(as_dict=True)))
    prk1 = json.dumps(handle_key(key._prek.export(as_dict=True)))
    return [
        Secret(
            kid=did_doc['verificationMethod'][0]['id'],
            type=VerificationMethodType.JSON_WEB_KEY_2020,  # TODO: Add support for more types
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=prk0
            )
        ),
        Secret(
            kid=f"{key.did}#X25519", #{key._prek.thumbprint()}",
            type=VerificationMethodType.JSON_WEB_KEY_2020,  # TODO: Add support for more types
            verification_material=VerificationMaterial(
                format=VerificationMaterialFormat.JWK,
                value=prk1
            )
        )
    ]

def secrets_from_doc(doc: DIDDoc) -> List[Secret]:
    return [Secret(
        kid=x.id,
        type=VerificationMethodType.JSON_WEB_KEY_2020,  # TODO: Add support for more types
        verification_material=VerificationMaterial(
            format=VerificationMaterialFormat.JWK,
            value=x.verification_material.value
        )
    ) for x in doc.verification_methods]

def resolver_from_key(key: SigningKey) -> ResolversConfig:
    doc = key_to_doc(key)
    class MockDIDResolverCustom(DIDResolverInMemory):
        def __init__(self):
            super().__init__(
                did_docs=[doc]
            )
    class MockSecretsResolverCustom(MockSecretsResolverInMemory):
        def __init__(self):
            super().__init__(
                secrets=secrets_from_doc(doc)
            )
    return ResolversConfig(MockSecretsResolverCustom(), MockDIDResolverCustom())

def resolver_from_keys(keys: Iterable[SigningKey]) -> ResolversConfig:
    docs = [key_to_doc(x) for x in keys]
    class MockDIDResolverCustom(DIDResolverInMemory):
        def __init__(self):
            super().__init__(
                did_docs=docs
            )
    # Secret is private key?
    class MockSecretsResolverCustom(MockSecretsResolverInMemory):
        def __init__(self):
            super().__init__(
                # secrets=[elem for sublist in [doc_to_secrets(x) for x in keys] for elem in sublist]
                secrets=[elem for sublist in [key_to_secrets(x) for x in keys] for elem in sublist]
            )
    return ResolversConfig(MockSecretsResolverCustom(), MockDIDResolverCustom())

# dd_secret = Secret(
#     kid="did:web:ee4acb6602.0.0.manufacturer.trustmanufacturer.med#la-yuOvYq31ARxkWdSwqL2FvSbohgrwvMxcGqTwgd_g",
#     type=VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020,
#     verification_material=VerificationMaterial(
#         format=VerificationMaterialFormat.JWK,
#         value=json.loads(b.jwk_public_key.export())
#     )
# )

# class MockSecretsResolverCustom(MockSecretsResolverInMemory):
#     def __init__(self):
#         super().__init__(
#             secrets=[
#                 dd_secret
#             ]
#         )

# class MockDIDResolverCustom(DIDResolverInMemory):
#     def __init__(self):
#         super().__init__(
#             did_docs=[
#                 dd
#             ]
#         )

# resolvers_config_custom = ResolversConfig(MockSecretsResolverCustom(), MockDIDResolverCustom())

# resolvers = [resolver_from_key(x) for x in SigningKey.objects.all()]

# resolver = resolver_from_keys(SigningKey.objects.all())

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
        # return key_to_secrets(signing_key)

    async def get_keys(self, kids: List[DID_URL]) -> List[DID_URL]:
        # TODO: extract '#' stripping
        signing_keys = await sync_to_async(SigningKey.objects.get)(did__in=[kid.split('#')[0] for kid in kids])
        # return [key_to_secrets(signing_key) for signing_key in signing_keys]

# resolver = ResolversConfig(DotMedSecretsResolver(), DotMedDIDResolver())
# sk0: SigningKey = SigningKey.objects.all()[0]
# sk1: SigningKey = SigningKey.objects.all()[1]


def ed_to_x(key: jwcrypto.jwk.JWK) -> jwcrypto.jwk.JWK:
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


import jwcrypto.jwk
k0 = jwcrypto.jwk.JWK.generate(kty='OKP', crv='Ed25519')
# k0 = jwcrypto.jwk.JWK.generate(kty='OKP', crv='X25519')
private_key0 = k0.export_to_pem(private_key=True, password=None)
public_key0 = k0.export_to_pem(password=None)
k1 = jwcrypto.jwk.JWK.generate(kty='OKP', crv='Ed25519')
# k1 = jwcrypto.jwk.JWK.generate(kty='OKP', crv='X25519')
private_key1 = k1.export_to_pem(private_key=True, password=None)
public_key1 = k1.export_to_pem(password=None)
# Look up the eddsa key type.
eddsa_key_types = [x for x in SigningKeyType.objects.all()]

sk0: SigningKey = SigningKey(
    did="did:web:distributor.trustmanufacturer.med",
    public_key=public_key0.decode(),
    private_key=private_key0.decode(),
    key_type=eddsa_key_types[0]
)
# sk0._prek = jwcrypto.jwk.JWK.generate(kty='OKP', crv='X25519')
sk0._prek = ed_to_x(k0)
sk1: SigningKey = SigningKey(
    did="did:web:manufacturer.trustmanufacturer.med",
    public_key=public_key1.decode(),
    private_key=private_key1.decode(),
    key_type=eddsa_key_types[0]
)
# sk1._prek = jwcrypto.jwk.JWK.generate(kty='OKP', crv='X25519')
sk1._prek = ed_to_x(k1)







# pprint(sk0.generate_did_document())
# pprint(sk0.jwk_public_key.export(as_dict=True))
# pprint(sk0.jwk_private_key.export(as_dict=True))
# pprint(sk1.generate_did_document())
# pprint(sk1.jwk_public_key.export(as_dict=True))
# pprint(sk1.jwk_private_key.export(as_dict=True))

resolver = resolver_from_keys([sk0, sk1])




d0 = async_to_sync(resolver.did_resolver.resolve)(sk0.did)
d1 = async_to_sync(resolver.did_resolver.resolve)(sk1.did)

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
    pack_config=PackEncryptedConfig(
        # enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW,
        # forward=False
    )
)

packed_msg = pack_result.packed_msg
pprint(json.loads(packed_msg))
print(110)

unpack_result = async_to_sync(unpack)(resolver, packed_msg)
pprint(unpack_result.message)
print(120)

print(f"Messages are equal: '{message == unpack_result.message}'")


# from peerdid.did_doc import DIDDocPeerDID as did_doc0
# e = did_doc0.from_json(d)
# # print(e)
# print(e.to_json())
