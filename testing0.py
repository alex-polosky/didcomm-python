from asgiref.sync import async_to_sync, sync_to_async
import json
from pprint import pprint

from didcomm.common.algorithms import AnonCryptAlg
from didcomm.common.resolvers import ResolversConfig
from didcomm.common.types import VerificationMaterial, VerificationMaterialFormat, VerificationMethodType
from didcomm.did_doc.did_doc import DIDCommService, DIDDoc, VerificationMethod
from didcomm.did_doc.did_resolver_in_memory import DIDResolverInMemory
from didcomm.message import Message
from didcomm.pack_encrypted import PackEncryptedConfig, PackEncryptedResult, pack_encrypted
from didcomm.protocols.routing.forward import PROFILE_DIDCOMM_AIP2_ENV_RFC587, PROFILE_DIDCOMM_V2
from didcomm.secrets.secrets_resolver import Secret
from didcomm.secrets.secrets_resolver_in_memory import SecretsResolverInMemory

import os

from didcomm.unpack import UnpackResult, unpack
os.environ.setdefault('DJANGO_FERNET_KEY', 'z597rAprVvMSXcKfVqOUCj556LYNiQJWfjVC14WFQ5d9bfNnwT')
os.environ.setdefault('DJANGO_SECRET_KEY', 'django-insecure-kr5_(8vjoc0-e$-@zm9axua_j2f3_qai2oqm__tfwsz)!m_v@i')
os.environ.setdefault('DJANGO_SETTINGS', 'dev')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'settings')
import django
django.setup()
from trustapi.didweb.models import SigningKey, SigningKeyType

class MockDIDResolverCustom(DIDResolverInMemory):
    def __init__(self):
        super().__init__(
            did_docs=[
                # ALICE
                DIDDoc(
                    did="did:example:alice",
                    authentication_kids=[
                        "did:example:alice#key-1",
                        "did:example:alice#key-2",
                        "did:example:alice#key-3",
                    ],
                    key_agreement_kids=[
                        "did:example:alice#key-x25519-not-in-secrets-1",
                        "did:example:alice#key-x25519-1",
                        "did:example:alice#key-p256-1",
                        "did:example:alice#key-p521-1",
                    ],
                    didcomm_services=[
                        DIDCommService(
                            id="did:example:123456789abcdefghi#didcomm-1",
                            service_endpoint="did:example:mediator1",
                            accept=[PROFILE_DIDCOMM_V2, PROFILE_DIDCOMM_AIP2_ENV_RFC587],
                            routing_keys=[
                                "did:example:mediator2#key-p521-1",
                            ],
                        )
                    ],
                    verification_methods=[
                        # ALICE_VERIFICATION_METHOD_KEY_AGREEM_X25519
                        VerificationMethod(
                            id="did:example:alice#key-x25519-1",
                            controller="did:example:alice#key-x25519-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "X25519",
                                        "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                                    }
                                )
                            )
                        ),
                        # ALICE_VERIFICATION_METHOD_KEY_AGREEM_P256
                        VerificationMethod(
                            id="did:example:alice#key-p256-1",
                            controller="did:example:alice#key-p256-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-256",
                                        "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                                        "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
                                    }
                                )
                            )
                        ),
                        # ALICE_VERIFICATION_METHOD_KEY_AGREEM_P521
                        VerificationMethod(
                            id="did:example:alice#key-p521-1",
                            controller="did:example:alice#key-p521-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-521",
                                        "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                                        "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
                                    }
                                )
                            )
                        ),
                        # ALICE_AUTH_METHOD_25519_NOT_IN_SECRET
                        VerificationMethod(
                            id="did:example:alice#key-not-in-secrets-1",
                            controller="did:example:alice#key-not-in-secrets-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "Ed25519",
                                        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                                    }
                                )
                            )
                        ),
                        # ALICE_AUTH_METHOD_25519
                        VerificationMethod(
                            id="did:example:alice#key-1",
                            controller="did:example:alice#key-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "Ed25519",
                                        "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                                    }
                                )
                            )
                        ),
                        # ALICE_AUTH_METHOD_P256
                        VerificationMethod(
                            id="did:example:alice#key-2",
                            controller="did:example:alice#key-2",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-256",
                                        "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                                        "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                                    }
                                )
                            )
                        ),
                        # ALICE_AUTH_METHOD_SECPP256K1
                        VerificationMethod(
                            id="did:example:alice#key-3",
                            controller="did:example:alice#key-3",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "secp256k1",
                                        "x": "aToW5EaTq5mlAf8C5ECYDSkqsJycrW-e1SQ6_GJcAOk",
                                        "y": "JAGX94caA21WKreXwYUaOCYTBMrqaX4KWIlsQZTHWCk",
                                    }
                                ),
                            ),
                        )
                    ]
                ),
                # BOB
                DIDDoc(
                    did="did:example:bob",
                    authentication_kids=[],
                    key_agreement_kids=[
                        "did:example:bob#key-x25519-1",
                        "did:example:bob#key-x25519-2",
                        "did:example:bob#key-x25519-3",
                        "did:example:bob#key-p256-1",
                        "did:example:bob#key-p256-2",
                        "did:example:bob#key-p384-1",
                        "did:example:bob#key-p384-2",
                        "did:example:bob#key-p521-1",
                        "did:example:bob#key-p521-2",
                    ],
                    didcomm_services=[],
                    verification_methods=[
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_1
                        VerificationMethod(
                            id="did:example:bob#key-x25519-1",
                            controller="did:example:bob#key-x25519-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "X25519",
                                        "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_2
                        VerificationMethod(
                            id="did:example:bob#key-x25519-2",
                            controller="did:example:bob#key-x25519-2",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "X25519",
                                        "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_X25519_3
                        VerificationMethod(
                            id="did:example:bob#key-x25519-3",
                            controller="did:example:bob#key-x25519-3",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "OKP",
                                        "crv": "X25519",
                                        "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_1
                        VerificationMethod(
                            id="did:example:bob#key-p256-1",
                            controller="did:example:bob#key-p256-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-256",
                                        "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                                        "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P256_2
                        VerificationMethod(
                            id="did:example:bob#key-p256-2",
                            controller="did:example:bob#key-p256-2",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-256",
                                        "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                                        "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_1
                        VerificationMethod(
                            id="did:example:bob#key-p384-1",
                            controller="did:example:bob#key-p384-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-384",
                                        "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                                        "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P384_2
                        VerificationMethod(
                            id="did:example:bob#key-p384-2",
                            controller="did:example:bob#key-p384-2",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-384",
                                        "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                                        "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_1
                        VerificationMethod(
                            id="did:example:bob#key-p521-1",
                            controller="did:example:bob#key-p521-1",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-521",
                                        "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                                        "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
                                    }
                                )
                            )
                        ),
                        # BOB_VERIFICATION_METHOD_KEY_AGREEM_P521_2
                        VerificationMethod(
                            id="did:example:bob#key-p521-2",
                            controller="did:example:bob#key-p521-2",
                            type=VerificationMethodType.JSON_WEB_KEY_2020,
                            verification_material=VerificationMaterial(
                                format=VerificationMaterialFormat.JWK,
                                value=json.dumps(
                                    {
                                        "kty": "EC",
                                        "crv": "P-521",
                                        "x": "ATp_WxCfIK_SriBoStmA0QrJc2pUR1djpen0VdpmogtnKxJbitiPq-HJXYXDKriXfVnkrl2i952MsIOMfD2j0Ots",
                                        "y": "AEJipR0Dc-aBZYDqN51SKHYSWs9hM58SmRY1MxgXANgZrPaq1EeGMGOjkbLMEJtBThdjXhkS5VlXMkF0cYhZELiH",
                                    }
                                )
                            )
                        )
                    ]
                )
            ]
        )
# Secret is private key?
class MockSecretsResolverCustom(SecretsResolverInMemory):
    def __init__(self):
        super().__init__(
            secrets=[
                # ALICE_SECRET_AUTH_KEY_ED25519
                Secret(
                    kid="did:example:alice#key-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "OKP",
                                "d": "pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                                "crv": "Ed25519",
                                "x": "G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww",
                            }
                        )
                    )
                ),
                # ALICE_SECRET_AUTH_KEY_P256
                Secret(
                    kid="did:example:alice#key-2",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "7TCIdt1rhThFtWcEiLnk_COEjh1ZfQhM4bW2wz-dp4A",
                                "crv": "P-256",
                                "x": "2syLh57B-dGpa0F8p1JrO6JU7UUSF6j7qL-vfk1eOoY",
                                "y": "BgsGtI7UPsObMRjdElxLOrgAO9JggNMjOcfzEPox18w",
                            }
                        )
                    )
                ),
                # ALICE_SECRET_KEY_AGREEMENT_KEY_X25519
                Secret(
                    kid="did:example:alice#key-x25519-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "OKP",
                                "d": "r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                                "crv": "X25519",
                                "x": "avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs",
                            }
                        )
                    )
                ),
                # ALICE_SECRET_KEY_AGREEMENT_KEY_P256
                Secret(
                    kid="did:example:alice#key-p256-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "sB0bYtpaXyp-h17dDpMx91N3Du1AdN4z1FUq02GbmLw",
                                "crv": "P-256",
                                "x": "L0crjMN1g0Ih4sYAJ_nGoHUck2cloltUpUVQDhF2nHE",
                                "y": "SxYgE7CmEJYi7IDhgK5jI4ZiajO8jPRZDldVhqFpYoo",
                            }
                        )
                    )
                ),
                # ALICE_SECRET_KEY_AGREEMENT_KEY_P521
                Secret(
                    kid="did:example:alice#key-p521-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "AQCQKE7rZpxPnX9RgjXxeywrAMp1fJsyFe4cir1gWj-8t8xWaM_E2qBkTTzyjbRBu-JPXHe_auT850iYmE34SkWi",
                                "crv": "P-521",
                                "x": "AHBEVPRhAv-WHDEvxVM9S0px9WxxwHL641Pemgk9sDdxvli9VpKCBdra5gg_4kupBDhz__AlaBgKOC_15J2Byptz",
                                "y": "AciGcHJCD_yMikQvlmqpkBbVqqbg93mMVcgvXBYAQPP-u9AF7adybwZrNfHWCKAQwGF9ugd0Zhg7mLMEszIONFRk",
                            }
                        )
                    )
                ),

                # BOB_SECRET_KEY_AGREEMENT_KEY_X25519_1
                Secret(
                    kid="did:example:bob#key-x25519-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "OKP",
                                "d": "b9NnuOCB0hm7YGNvaE9DMhwH_wjZA1-gWD6dA0JWdL0",
                                "crv": "X25519",
                                "x": "GDTrI66K0pFfO54tlCSvfjjNapIs44dzpneBgyx0S3E",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_X25519_2 = 
                Secret(
                    kid="did:example:bob#key-x25519-2",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "OKP",
                                "d": "p-vteoF1gopny1HXywt76xz_uC83UUmrgszsI-ThBKk",
                                "crv": "X25519",
                                "x": "UT9S3F5ep16KSNBBShU2wh3qSfqYjlasZimn0mB8_VM",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_X25519_3
                Secret(
                    kid="did:example:bob#key-x25519-3",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "OKP",
                                "d": "f9WJeuQXEItkGM8shN4dqFr5fLQLBasHnWZ-8dPaSo0",
                                "crv": "X25519",
                                "x": "82k2BTUiywKv49fKLZa-WwDi8RBf0tB0M8bvSAUQ3yY",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_P256_1
                Secret(
                    kid="did:example:bob#key-p256-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "PgwHnlXxt8pwR6OCTUwwWx-P51BiLkFZyqHzquKddXQ",
                                "crv": "P-256",
                                "x": "FQVaTOksf-XsCUrt4J1L2UGvtWaDwpboVlqbKBY2AIo",
                                "y": "6XFB9PYo7dyC5ViJSO9uXNYkxTJWn0d_mqJ__ZYhcNY",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_P256_2
                Secret(
                    kid="did:example:bob#key-p256-2",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "agKz7HS8mIwqO40Q2dwm_Zi70IdYFtonN5sZecQoxYU",
                                "crv": "P-256",
                                "x": "n0yBsGrwGZup9ywKhzD4KoORGicilzIUyfcXb1CSwe0",
                                "y": "ov0buZJ8GHzV128jmCw1CaFbajZoFFmiJDbMrceCXIw",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_P384_1
                Secret(
                    kid="did:example:bob#key-p384-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "ajqcWbYA0UDBKfAhkSkeiVjMMt8l-5rcknvEv9t_Os6M8s-HisdywvNCX4CGd_xY",
                                "crv": "P-384",
                                "x": "MvnE_OwKoTcJVfHyTX-DLSRhhNwlu5LNoQ5UWD9Jmgtdxp_kpjsMuTTBnxg5RF_Y",
                                "y": "X_3HJBcKFQEG35PZbEOBn8u9_z8V1F9V1Kv-Vh0aSzmH-y9aOuDJUE3D4Hvmi5l7",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_P384_2
                Secret(
                    kid="did:example:bob#key-p384-2",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "OiwhRotK188BtbQy0XBO8PljSKYI6CCD-nE_ZUzK7o81tk3imDOuQ-jrSWaIkI-T",
                                "crv": "P-384",
                                "x": "2x3HOTvR8e-Tu6U4UqMd1wUWsNXMD0RgIunZTMcZsS-zWOwDgsrhYVHmv3k_DjV3",
                                "y": "W9LLaBjlWYcXUxOf6ECSfcXKaC3-K9z4hCoP0PS87Q_4ExMgIwxVCXUEB6nf0GDd",
                            }
                        )
                    )
                ),
                # BOB_SECRET_KEY_AGREEMENT_KEY_P521_1 = 
                Secret(
                    kid="did:example:bob#key-p521-1",
                    type=VerificationMethodType.JSON_WEB_KEY_2020,
                    verification_material=VerificationMaterial(
                        format=VerificationMaterialFormat.JWK,
                        value=json.dumps(
                            {
                                "kty": "EC",
                                "d": "AV5ocjvy7PkPgNrSuvCxtG70NMj6iTabvvjSLbsdd8OdI9HlXYlFR7RdBbgLUTruvaIRhjEAE9gNTH6rWUIdfuj6",
                                "crv": "P-521",
                                "x": "Af9O5THFENlqQbh2Ehipt1Yf4gAd9RCa3QzPktfcgUIFADMc4kAaYVViTaDOuvVS2vMS1KZe0D5kXedSXPQ3QbHi",
                                "y": "ATZVigRQ7UdGsQ9j-omyff6JIeeUv3CBWYsZ0l6x3C_SYqhqVV7dEG-TafCCNiIxs8qeUiXQ8cHWVclqkH4Lo1qH",
                            }
                        )
                    )
                )
            ]
        )

resolver = ResolversConfig(MockSecretsResolverCustom(), MockDIDResolverCustom())

message = Message(
    id="1234567890",
    frm='did:example:alice',
    to=['did:example:bob'],
    type="application/testing",
    created_time=1516269022,
    expires_time=1516385931,
    body={
        "aaa": 1,
        "bbb": 2
    }
)

pack_result: PackEncryptedResult = async_to_sync(pack_encrypted)(
    resolvers_config=resolver,
    message=message,
    frm='did:example:alice',
    to='did:example:bob',
    pack_config=PackEncryptedConfig(
        enc_alg_anon=AnonCryptAlg.XC20P_ECDH_ES_A256KW,
        forward=False
    )
)

packed_msg = pack_result.packed_msg
pprint(json.loads(packed_msg))
print(110)

unpack_result: UnpackResult = async_to_sync(unpack)(resolver, packed_msg)
pprint(unpack_result.message)
print(120)
