import struct
from constants import *


def pack_result(result):
    header_format = '<BHI'
    buffer = struct.pack(header_format, result[0], result[1], result[2])

    # result[1] contains the returned code value
    if result[1] == RESPONSE_REGISTER_SUCCESS:
        buffer += struct.pack('<16s', result[3])

    elif result[1] == RESPONSE_GET_CLIENTS_SUCCESS:
        clients_array = result[CLIENTS_ARRAY_POSITION]
        buffer += pack_all_clients(clients_array)

    elif result[1] == RESPONSE_GET_PUBLIC_KEY_SUCCESS:
        client_id, public_key = result[3][0], result[3][1]
        buffer += struct.pack('<16s160s', client_id, public_key)

    elif result[1] == RESPONSE_SENDING_MESSAGE_SUCCESS:
        receiver_id, message_id = result[3][0], result[3][1]
        buffer += struct.pack('<16sI', receiver_id, message_id)

    elif result[1] == RESPONSE_PULLING_MESSAGES_SUCCESS:
        messages_array = result[MESSAGES_ARRAY_POSITION]
        if messages_array is not None:
            buffer += pack_all_messages(messages_array)

    return buffer


def pack_all_clients(clients_array):
    buffer = b''
    for client in clients_array:
        buffer += struct.pack('<16s255s', client[0], client[1])
    return buffer


def pack_all_messages(messages_array):
    buffer = b''
    for message in messages_array:
        message_format = f'<16sIBI{len(message.content)}s'
        buffer += struct.pack(message_format, message.from_client, message.id,
                              message.message_type, len(message.content), message.content)
    return buffer