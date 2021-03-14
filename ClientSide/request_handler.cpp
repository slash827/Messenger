#include <string>
#include <iostream>
#include <fstream>
#include <boost/algorithm/hex.hpp>
#include "access_files.h"
#include "encryptions.h"

bool is_symmetric_connected(map<string, ClientInfo>* all_clients, string username)
{
	return (*all_clients)[username].symmetric_key != "";
}

uint8_t* input_client_name(map<string, ClientInfo>* all_clients, string *username)
{
	// this function takes a username from the keyboard, and returns it's id
	if (all_clients->empty())
	{
		error_displayer(NO_CLIENTS_IN_THE_SERVER);
		return nullptr;
	}
	uint8_t* client_ptr;
	LOG("please enter the username:");

	do
	{
		string client_name;
		getline(cin >> ws, client_name);
		while (client_name.length() >= NAME_LENGTH)
		{
			error_displayer(TOO_BIG_NAME);
			getline(cin >> ws, client_name);
		}

		client_ptr = get_client_id_by_name(client_name, all_clients);
		if (client_ptr == nullptr)
		{
			error_displayer(NAME_IS_NOT_IN_DB);
			return nullptr;
		}
		else *username = client_name;

	} while (client_ptr == nullptr);

	return client_ptr;
}

uint8_t* get_client_id_by_name(string name, map<string, ClientInfo>* all_clients)
{
	if (all_clients->find(name) != all_clients->end())
	{
		ClientInfo* client_ptr = &(*all_clients)[name];
		return client_ptr->client_id;
	}
	else
		return nullptr;
}

void send_text_message_request(Request* request, string* payload, ClientInfo* other_client)
{
	uint8_t message_type = SEND_TEXT_MESSAGE_TYPE;
	*payload += message_type;

	LOG("please enter you message now:");
	string client_message = "";

	// here we take the message as input from the keyboard
	char c;
	for (uint32_t i = 0; i < UINT32_MAX && cin.get(c) && c != '\n'; i++)
		client_message += c;

	string cipher_message = encrypt_symmetric(client_message, other_client->symmetric_key);
	
	// here we calculate the length of the message and stores it
	uint32_t message_size = cipher_message.length();
	uint8_t sizes[4] = { uint8_t(message_size), uint8_t(message_size >> 8), 
						uint8_t(message_size >> 16), uint8_t(message_size >> 24) };
	
	for (int j = 0; j < 4; j++)
		*payload += sizes[j];

	*payload += cipher_message;
	request->payload_size += message_size;
}

void send_symmetric_key_request(Request* request, string* payload, ClientInfo* other_client)
{
	uint8_t message_type = SEND_SYMMETRIC_KEY_TYPE;
	*payload += message_type;
	symmetric_key_create(&other_client->symmetric_key);

	string encrypted_key = asymmetric_encypt(other_client->symmetric_key, other_client->public_key);
	uint8_t sizes[4] = { (uint8_t)encrypted_key.length(), 0, 0, 0 };
	for (int j = 0; j < 4; j++)
		*payload += sizes[j];

	*payload += encrypted_key;
	request->payload_size += encrypted_key.length();
}

void ask_symmetric_key_request(Request* request, string* payload)
{
	uint8_t message_type = ASK_SYMMETRIC_KEY_TYPE;
	*payload += message_type;

	uint8_t content_size[4] = { 0 };
	for (int j = 0; j < 4; j++)
		*payload += content_size[j];
}

int send_message_request(Request* request, string keyboard_input, string *payload, 
							map<string, ClientInfo>* all_clients, ClientInfo *this_client)
{
	request->code = CODE_FOR_SENDING_MESSAGE;
	uint8_t *client_ptr;
	string client_username = "";
	client_ptr = input_client_name(all_clients, &client_username);
	if (client_ptr == nullptr)
		return DISPLAY_ERROR;

	request->payload_size = CLIENT_ID_LENGTH + MESSAGE_TYPE_FIELD_LENGTH;
	request->payload_size += MESSAGE_SIZE_FIELD_LENGTH;

	for (int j = 0; j < CLIENT_ID_LENGTH; j++)
		*payload += client_ptr[j];

	bool symmetric_connect = is_symmetric_connected(all_clients, client_username);
	ClientInfo *other_client = &(*all_clients)[client_username];

	if (keyboard_input == "5" && symmetric_connect)
		send_text_message_request(request, payload, other_client);
	if (keyboard_input == "5" && !symmetric_connect)
	{
		error_displayer(ACTION_REQUIRES_SYMMETRIC_CONNECTION);
		return DISPLAY_ERROR;
	}

	else if (keyboard_input == "51" && !symmetric_connect)
		ask_symmetric_key_request(request, payload);
	else if (keyboard_input == "51" && symmetric_connect)
	{
		error_displayer(ACTION_REQUIRES_NON_SYMMETRIC_CONNECTION);
		return DISPLAY_ERROR;
	}

	else  if (keyboard_input == "52" && !symmetric_connect)
		send_symmetric_key_request(request, payload, other_client);
	else if (keyboard_input == "52" && symmetric_connect)
	{
		error_displayer(ACTION_REQUIRES_NON_SYMMETRIC_CONNECTION);
		return DISPLAY_ERROR;
	}

	return PACKED_REGISTRATION;
}

int pull_messages_request(Request* request)
{
	request->code = CODE_FOR_PULLING_MESSAGES;
	request->payload_size = 0;
	return PACKED_REGISTRATION;
}

int get_public_key_request(Request* request, string *payload, map<string, ClientInfo>* all_clients)
{
	uint8_t *client_ptr;
	string client_username = "";
	client_ptr = input_client_name(all_clients, &client_username);
	
	if (client_ptr == nullptr)
		return DISPLAY_ERROR;

	for (int j = 0; j < CLIENT_ID_LENGTH; j++)
		*payload += client_ptr[j];

	request->code = CODE_FOR_GET_PUBLIC_KEY;
	request->payload_size = CLIENT_ID_LENGTH;

	return PACKED_REGISTRATION;
}

int get_clients_request(Request* request)
{
	request->code = CODE_FOR_GET_ALL_CLIENTS;
	request->payload_size = 0;
	return PACKED_REGISTRATION;
}

int register_request(Request* request, string *payload, ClientInfo* this_client)
{
	if (is_registered())
	{
		error_displayer(ALREADY_REGISTERED);
		return DISPLAY_ERROR;
	}

	string username;
	LOG("please enter a name to register to the server:");
	getline(cin >> ws, username);

	// here we check that name length is <= 254
	while (username.length() >= NAME_LENGTH)
	{
		error_displayer(TOO_BIG_NAME);
		getline(cin >> ws, username);
	}

	this_client->name = username;

	// here we normalize the name to have 255 chars
	int i, add_amount = NAME_LENGTH - username.length();
	for (i = 1; i <= add_amount; i++)
		username.push_back('\0');

	generate_asymmetric_keys(&this_client->private_key, this_client->public_key);

	request->code = CODE_FOR_REGISTER;
	request->payload_size = NAME_LENGTH + PUBLIC_KEY_LENGTH;
	*payload = username;
	for (i = 0; i < PUBLIC_KEY_LENGTH; i++)
		*payload += this_client->public_key[i];

	return PACKED_REGISTRATION;
}

bool is_registered()
{
	ifstream infile("me.info");
	bool is_reg = infile.good();
	infile.close();
	return is_reg;
}

void display_menu()
{
	string menu = "MessageU client at your service.\n\n";
	menu += "1) Register\n";
	menu += "2) Request for clients list \n";
	menu += "3) Request for public key \n";
	menu += "4) Request for waiting messages \n";
	menu += "5) Send a text message \n";
	menu += "51) Send a request for symmetric key \n";
	menu += "52) Send your symmetric key \n";
	menu += "0) Exit client\n? ";
	cout << menu;
}

int identify_request_type(Request* request, string *payload, ClientInfo *this_client, 
							map<string, ClientInfo> *all_clients)
{
	string keyboard_input;
	cin >> keyboard_input;
	if (keyboard_input.length() > MENU_MAX_INPUT_LENGTH)
	{
		error_displayer(TOO_BIG_REQUEST_INPUT);
		return DISPLAY_ERROR;
	}

	if (keyboard_input == "0")
		return FINISH_PROGRAM;

	request->version = CLIENT_VERSION;

	if (keyboard_input == "1")
		return register_request(request, payload, this_client);

	if (is_registered())
		me_info_to_client_info(this_client, request);
	else
	{
		error_displayer(REGISTER_ONLY_OPERATION);
		return DISPLAY_ERROR;
	}

	if (keyboard_input == "2")
		return get_clients_request(request);
	else if (keyboard_input == "3")
		return get_public_key_request(request, payload, all_clients);
	else if (keyboard_input == "4")
		return pull_messages_request(request);
	else if (keyboard_input == "5" || keyboard_input == "51" || keyboard_input == "52")
		return send_message_request(request, keyboard_input, payload, all_clients, this_client);
	else
	{
		error_displayer(INVALID_REQUEST_TYPE);
		return DISPLAY_ERROR;
	}
}

void error_displayer(int error_number)
{
	switch (error_number)
	{
	case TOO_BIG_REQUEST_INPUT:
		LOG("the input that you have entered is too big please try again");
		break;
	case INVALID_REQUEST_TYPE:
		LOG("the option that you requested is not available");
		break;
	case ALREADY_REGISTERED:
		LOG("this client is already registered");
		break;
	case TOO_BIG_NAME:
		LOG("the name that you have entered is too long please try again:");
		return;
	case RESPONSE_GENERAL_ERROR:
		LOG("server responded with an error");
		break;
	case CLIENT_IS_NOT_REGISTERED:
		LOG("you need to be registered for this request");
		break;
	case WRONG_CLIENT_ID_LENGTH:
		LOG("the client id that you have entered is not in the correct size please try again:");
		break;
	case NAME_IS_NOT_IN_DB:
		LOG("the name that you have entered is not in the database please try again:");
		break;
	case REGISTER_ONLY_OPERATION:
		LOG("you need to be registered to use this option!");
		break;
	case INVALID_PORT_NUMBER:
		LOG("error, the given port is wrong");
		break;
	case INVALID_IP_ADDRESS:
		LOG("error, the given ip address is wrong");
		break;
	case NO_CLIENTS_IN_THE_SERVER:
		LOG("the command that you ask for is not possible because there are currently no other registered clients");
		break;
	case ACTION_REQUIRES_SYMMETRIC_CONNECTION:
		LOG("error, a symmetric connection with the client is needed for this operation");
		break;
	case ACTION_REQUIRES_NON_SYMMETRIC_CONNECTION:
		LOG("error, there should not be a symmetric connection with the client for this operation");
		break;
	}
	LOG("");
}
