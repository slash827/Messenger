import uuid
import struct
import db_access as db
from datetime import datetime
from constants import *

# the database object
db_obj = db.database_obj


def request_identify(data):
    # first make sure that data length is al least the header length
    if len(data) < FULL_HEADER_LENGTH:
        return error_handling(TOO_LITTLE_PACKAGE_ARRIVED)

    # unpacks the data, identifies the code interpret it and returns
    # the result back to the main server file
    full_header = unpack_message(data)
    client_version = full_header[HEADER_SERVER_VERSION_POSITION]

    # here we make sure that the client version is 1 or 2
    if 1 <= client_version <= 2:
        return extract_code(full_header, data)

    # else there is an error in the client's version
    return error_handling(INVALID_CLIENT_VERSION)


def unpack_message(data):
    # this format extracts the header from the received data
    header_format = '<16sBBI'
    full_header = struct.unpack_from(header_format, data)
    return full_header


def extract_code(full_header, buffer):
    # this function directs the request to the proper function that will handle it
    code = full_header[HEADER_CODE_POSITION]

    if code == CODE_FOR_REGISTER:
        return register_client(full_header, buffer)

    elif code == CODE_FOR_GET_ALL_CLIENTS:
        return get_clients_list(full_header, buffer)

    elif code == CODE_FOR_GET_PUBLIC_KEY:
        return get_public_key(full_header, buffer)

    elif code == CODE_FOR_SENDING_MESSAGE:
        return identify_message(full_header, buffer)

    elif code == CODE_FOR_PULLING_MESSAGES:
        return pull_messages(full_header, buffer)

    else:
        return error_handling(INVALID_CODE)


def register_client(full_header, buffer):
    # first we make sure that the payload's actual length is in the right size
    # since 22 for header + 255 for name + 160 for public key = 437 length
    if len(buffer) != FULL_HEADER_LENGTH + NAME_LENGTH + PUBLIC_KEY_LENGTH:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    # then make sure that the payload size field in the header is in the appropriate length
    payload_size_field = full_header[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    if payload_size_field != NAME_LENGTH + PUBLIC_KEY_LENGTH:
        return error_handling(WRONG_PAYLOAD_SIZE_FIELD)

    # here we check that the name suggested is not already registered in the database
    clients_list = db_obj.get_all_clients_names()
    name = extract_name_from_buffer(buffer)
    print(f'the name that a client wishes to register as is: {name}')

    if name in clients_list:
        print(f'name {name} already taken')
        return error_handling(NAME_ALREADY_TAKEN)

    # now we can create a public key and id for the client
    # since the position is from 22 for header + 255 for name = 277 and public key's length = 160
    public_key = struct.unpack_from('<160s', buffer, 277)[0]
    client_id = uuid.uuid4().bytes_le

    # then we create a new client record and adds it to the database then return results
    new_client = db.Client_Record(client_id, name, public_key, last_seen=datetime.now())

    # check if we can add the client with no problem or return an error
    result = db_obj.add_client(new_client)
    if result == ERROR_ADDING_CLIENT:
        return error_handling(DATABASE_ERROR)

    # check for a possible SQL injection
    if result == POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    print(f'the client: {name} was added successfully to the DB')
    # here client_id length = payload length = 16 bytes
    return [SERVER_VERSION, RESPONSE_REGISTER_SUCCESS, CLIENT_ID_LENGTH, client_id]


def extract_name_from_buffer(buffer):
    # where name length = 255
    whole_name = struct.unpack_from('255s', buffer, PAYLOAD_START_POSITION)[0]
    name = ''.join([chr(item) for item in whole_name if item])
    return name


def get_clients_list(full_header, buffer):
    # first we make sure that the payload's actual length is 0
    # and header's length is 22 and we make sure that the payload size field is 0
    if len(buffer) != FULL_HEADER_LENGTH:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    payload_size_field = full_header[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    if payload_size_field != EMPTY_PAYLOAD_LENGTH:
        return error_handling(WRONG_PAYLOAD_SIZE_FIELD)

    # here we retrieve from the DB all clients info except the one that asks for that
    client_id = full_header[HEADER_CLIENT_ID_POSITION]
    result = db_obj.get_all_clients_info_except(client_id)
    if result is None:
        return error_handling(CLIENT_NOT_IN_DATABASE)

    # check for a possible SQL injection
    if result == POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    # adding '\0' to the names so that the length of the names will be 255
    for i in range(len(result)):
        result[i][1] += (NAME_LENGTH - len(result[i][0])) * b'\0'

    # payload size = 16 for each client's id and 255 for each client's name
    result_payload_size = len(result) * (CLIENT_ID_LENGTH + NAME_LENGTH)
    return [SERVER_VERSION, RESPONSE_GET_CLIENTS_SUCCESS, result_payload_size, result]


def get_public_key(full_header, buffer):
    # first we make sure that the payload's actual length is 16
    # and header's length is 22 and we make sure that the payload size field is 16
    if len(buffer) != FULL_HEADER_LENGTH + CLIENT_ID_LENGTH:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    payload_size_field = full_header[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    if payload_size_field != CLIENT_ID_LENGTH:
        return error_handling(WRONG_PAYLOAD_SIZE_FIELD)

    # here we get the required client's id to get his public key
    requested_client_id = struct.unpack_from('<16s', buffer, FULL_HEADER_LENGTH)[0]

    # here we get the required public key
    public_key = db_obj.get_client_public_key(requested_client_id)
    # check for a possible SQL injection
    if public_key is POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    # in case the required public key is of a client id that is not in the DB
    if public_key is None:
        return error_handling(CLIENT_NOT_IN_DATABASE)

    result = [requested_client_id, public_key]
    return [SERVER_VERSION, RESPONSE_GET_PUBLIC_KEY_SUCCESS, PUBLIC_KEY_LENGTH + CLIENT_ID_LENGTH, result]


def identify_message(full_header, buffer):
    # header length = 22 + message header length = 21 = 43, a message should be with
    # length of at least that sum
    if len(buffer) < FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    sender_id = full_header[HEADER_CLIENT_ID_POSITION]
    receiver_id, message_type, content_size = \
        struct.unpack_from('<16sBI', buffer, PAYLOAD_START_POSITION)

    # then we should make sure that the payload size field equals to the actual length
    payload_size_field = full_header[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    if message_type != SEND_TEXT_MESSAGE_TYPE and len(buffer) != \
            FULL_HEADER_LENGTH + payload_size_field:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    # here we make sure that both the sender and receiver are registered to the server
    result = [db_obj.get_client(sender_id), db_obj.get_client(receiver_id)]
    if result[0] is None or result[1] is None:
        return error_handling(CLIENT_NOT_IN_DATABASE)

    # if there is a possible injection in the id of either sender or receiver id then returns an error
    if result[0] == POSSIBLE_INJECTION or result[1] == POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    if message_type == ASK_SYMMETRIC_KEY_TYPE:
        message = db.Message_Record(0, receiver_id, sender_id, message_type, '')
        return ask_symmetric_key(buffer, message, content_size)

    elif message_type == SEND_SYMMETRIC_KEY_TYPE:
        return send_symmetric_key(buffer, sender_id, receiver_id, message_type, content_size)

    elif message_type == SEND_TEXT_MESSAGE_TYPE:
        return send_text_message(buffer, sender_id, receiver_id, message_type, content_size, payload_size_field)
    else:
        return error_handling(INVALID_MESSAGE_TYPE)


def ask_symmetric_key(buffer, message, content_size):
    if content_size != 0 or len(buffer) != FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH:
        return error_handling(INVALID_MESSAGE_CONTENT_SIZE)

    return check_message_validity(message)


def send_symmetric_key(buffer, sender_id, receiver_id, message_type, content_size):
    # first we make sure that the content size field is equal to the symmetric key's length
    # then we make sure that the package's length is equal to the sum of the header + message_header + symmetric key's length
    if len(buffer) != FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH + content_size:
        return error_handling(INVALID_MESSAGE_CONTENT_SIZE)

    # since CIPHERED SYMMETRIC_KEY_LENGTH = 128
    sum_of_headers = FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH
    message_content = struct.unpack_from('<128s', buffer, sum_of_headers)[0]
    message = db.Message_Record(0, receiver_id, sender_id, message_type, message_content)

    return check_message_validity(message)


def send_text_message(buffer, sender_id, receiver_id, message_type, content_size, original_payload_size):    # if it's a big text message then there is a special process for it
    if original_payload_size + FULL_HEADER_LENGTH > 1024:
        result = [buffer, sender_id, receiver_id]
        return [SERVER_VERSION, PROCESSING_BIG_TEXT_MESSAGE, result, original_payload_size]

    # make sure that the actual message content is bigger than 0 and the content size field is bigger than 0
    if content_size == 0 or len(buffer) != FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH + content_size:
        return error_handling(INVALID_MESSAGE_CONTENT_SIZE)

    content_format = f'<{content_size}s'
    sum_of_headers = FULL_HEADER_LENGTH + SEND_MESSAGE_HEADER_LENGTH
    message_content = struct.unpack_from(content_format, buffer, sum_of_headers)[0]
    message = db.Message_Record(0, receiver_id, sender_id, message_type, message_content)

    return check_message_validity(message)


def handle_big_packs(result, sock):
    # this function is called only for a very big text message
    payload_size_field = result[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    message_length = payload_size_field - SEND_MESSAGE_HEADER_LENGTH
    total_content = 1024 - FULL_HEADER_LENGTH - SEND_MESSAGE_HEADER_LENGTH
    buffer = result[2][0]
    sender_id, receiver_id = result[2][1], result[2][2]
    message_content = buffer[FULL_HEADER_LENGTH+SEND_MESSAGE_HEADER_LENGTH:]

    # in this loop we will continue to receive data until all the message has been processed
    while total_content < message_length:
        recv_data = sock.recv(1024)
        message_content += recv_data
        total_content += len(recv_data)

    # now all the message content has been received and ready to be stored in the DB
    message = db.Message_Record(0, receiver_id, sender_id, SEND_TEXT_MESSAGE_TYPE, message_content)
    return check_message_validity(message)


def check_message_validity(message):
    # first we try to add the message to the DB
    message.id = db_obj.add_message(message)

    if message.id == SQL_GENERAL_ERROR:
        return error_handling(DATABASE_ERROR)

    if message.id == POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    # only if a successful add has made then we return a proper response array
    result = [message.to_client, message.id]
    payload_size = CLIENT_ID_LENGTH + MESSAGE_ID_LENGTH
    return [SERVER_VERSION, RESPONSE_SENDING_MESSAGE_SUCCESS, payload_size, result]


def pull_messages(full_header, buffer):
    # first we make sure that the payload's actual length is 0
    # and header's length is 22 and we make sure that the payload size field is 0
    payload_size_field = full_header[HEADER_PAYLOAD_SIZE_FIELD_POSITION]
    if len(buffer) != FULL_HEADER_LENGTH or payload_size_field != EMPTY_PAYLOAD_LENGTH:
        return error_handling(WRONG_PAYLOAD_LENGTH)

    # here we retrieve all the messages that were needed to be pulled
    this_client_id = full_header[HEADER_CLIENT_ID_POSITION]
    messages_array = db_obj.remove_messages_for_client(this_client_id)
    if messages_array == POSSIBLE_INJECTION:
        return error_handling(POSSIBLE_INJECTION)

    # here we calculate the total payload size
    payload_size = 0
    if messages_array is not None:
        for message in messages_array:
            payload_size += RECEIVE_MESSAGE_HEADER_LENGTH + len(message.content)

    return [SERVER_VERSION, RESPONSE_PULLING_MESSAGES_SUCCESS, payload_size, messages_array]


def error_handling(error_id):
    print(f'the error of the client has number: {error_id}')
    return [SERVER_VERSION, RESPONSE_GENERAL_ERROR, EMPTY_PAYLOAD_LENGTH]
