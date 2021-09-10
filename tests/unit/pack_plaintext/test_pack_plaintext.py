import pytest

from didcomm.core.serialization import json_str_to_dict
from didcomm.pack_plaintext import pack_plaintext
from didcomm.unpack import unpack
from tests.test_vectors.didcomm_messages.messages import (
    TEST_MESSAGE,
    attachment_json_msg,
    attachment_links_msg,
    attachment_base64_msg,
    minimal_msg,
    attachment_multi_1_msg,
    attachment_multi_2_msg,
)
from tests.test_vectors.didcomm_messages.spec.spec_test_vectors_plaintext import (
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE,
)
from tests.test_vectors.didcomm_messages.tests.test_vectors_plaintext_positive import (
    TEST_PLAINTEXT_ATTACHMENT_BASE64,
    TEST_PLAINTEXT_ATTACHMENT_LINKS,
    TEST_PLAINTEXT_ATTACHMENT_JSON,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_1,
    TEST_PLAINTEXT_ATTACHMENT_MULTI_2,
    TEST_PLAINTEXT_DIDCOMM_MESSAGE_MINIMAL,
)


async def check_pack_simple_plaintext(msg, expected_json, resolvers_config_bob):
    packed_msg = await pack_plaintext(resolvers_config_bob, msg)
    assert json_str_to_dict(packed_msg) == json_str_to_dict(expected_json)

    unpacked_msg = await unpack(resolvers_config_bob, packed_msg)
    assert unpacked_msg.message == msg


@pytest.mark.asyncio
async def test_pack_simple_plaintext(resolvers_config_bob):
    await check_pack_simple_plaintext(
        TEST_MESSAGE, TEST_PLAINTEXT_DIDCOMM_MESSAGE_SIMPLE, resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_minimal_plaintext(resolvers_config_bob):
    await check_pack_simple_plaintext(
        minimal_msg(), TEST_PLAINTEXT_DIDCOMM_MESSAGE_MINIMAL, resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_attachments_base64(resolvers_config_bob):
    await check_pack_simple_plaintext(
        attachment_base64_msg(), TEST_PLAINTEXT_ATTACHMENT_BASE64, resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_attachments_links(resolvers_config_bob):
    await check_pack_simple_plaintext(
        attachment_links_msg(), TEST_PLAINTEXT_ATTACHMENT_LINKS, resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_attachments_json(resolvers_config_bob):
    await check_pack_simple_plaintext(
        attachment_json_msg(), TEST_PLAINTEXT_ATTACHMENT_JSON, resolvers_config_bob
    )


@pytest.mark.asyncio
async def test_pack_attachments_multi1(resolvers_config_bob):
    await check_pack_simple_plaintext(
        attachment_multi_1_msg(),
        TEST_PLAINTEXT_ATTACHMENT_MULTI_1,
        resolvers_config_bob,
    )


@pytest.mark.asyncio
async def test_pack_attachments_multi2(resolvers_config_bob):
    await check_pack_simple_plaintext(
        attachment_multi_2_msg(),
        TEST_PLAINTEXT_ATTACHMENT_MULTI_2,
        resolvers_config_bob,
    )