#include <iostream>
#include <string>
#include <memory>
#include <map>
#include "response_handler.h"
#include "encryptions.h"
using namespace std;

void copy_client_id(uint8_t* requested_client_id, uint8_t* response_payload)
{
	for (int i = 0; i < CLIENT_ID_LENGTH; i++)
		requested_client_id[i] = response_payload[i];
}

bool compare_client_id(uint8_t* requested_client_id, uint8_t* response_payload)
{
	for (int i = 0; i < CLIENT_ID_LENGTH; i++)
		if (requested_client_id[i] != response_payload[i])
			return false;
	return true;
}

void handle_registration(ClientInfo* this_client, uint8_t* response_payload, string *username)
{
	copy_client_id(this_client->client_id, response_payload);
	client_info_to_file(username, this_client);
	LOG("registered successfully!");
}

void handle_get_clients(Response *response ,map<string, ClientInfo> *all_clients, uint8_t *response_payload)
{
	uint32_t payload_size = response->payload_size, i = 0, j;
	
	if (payload_size == 0)
		LOG("\nthere are currently no registered clients in the server");
	else
		LOG("\nthe client's list of names is: ");

	while (i < payload_size)
	{
		ClientInfo the_client;
		copy_client_id(the_client.client_id, response_payload);
		response_payload += CLIENT_ID_LENGTH;

		the_client.name = "";
		j = 0;
		while (j < NAME_LENGTH && response_payload[j] != '\0')
			the_client.name += response_payload[j++];

		all_clients->insert({ the_client.name, the_client });
		i += CLIENT_ID_LENGTH + NAME_LENGTH;
		response_payload += NAME_LENGTH;
		LOG("client's name is: " + the_client.name);
	}
	LOG("");
}

void handle_get_public_key(map<string, ClientInfo> *all_clients, uint8_t *response_payload)
{
	uint8_t requested_client_id[CLIENT_ID_LENGTH];
	copy_client_id(requested_client_id, response_payload);
	response_payload += CLIENT_ID_LENGTH;
	string client_name;

	for (auto &x : *all_clients)
	{
		ClientInfo* current_client = &x.second;
		if (compare_client_id(current_client->client_id, requested_client_id))
		{
			for (int i = 0; i < PUBLIC_KEY_LENGTH; i++)
				current_client->public_key[i] = response_payload[i];
			client_name = x.first;
			LOG("received public key successfully!");
		}
	}
}

string get_client_name_by_id(map<string, ClientInfo> *all_clients, uint8_t *client_id)
{
	for (auto& x : *all_clients)
	{
		ClientInfo* current_client = &x.second;
		if (compare_client_id(current_client->client_id, client_id))
			return x.first;
	}
	return ""; // in case not found
}

void print_message(string client_name, uint8_t message_type, uint32_t message_size, uint8_t* message_content, string* symmetric_key)
{
	LOG("From: " + client_name);
	LOG("Content: ");
	if (message_type == ASK_SYMMETRIC_KEY_TYPE)
		LOG("Request for symmetric key");
	else if (message_type == SEND_SYMMETRIC_KEY_TYPE)
		LOG("symmetric key received");
	else
	{
		string s_message_content = "";
		for (uint32_t i = 0; i < message_size; i++)
			s_message_content += message_content[i];
		LOG(decrypt_symmetric(s_message_content, *symmetric_key) << '\n');
	}
}

void handle_pulling_messages(uint8_t* response_payload, uint32_t payload_size, 
	map<string, ClientInfo>* all_clients, ClientInfo* this_client)
{
	uint32_t i = 0, j, message_size;
	uint8_t message_type;
	if (payload_size == 0)
		LOG("\nthere are currently no new messages");
	
	LOG("");
	while (i < payload_size)
	{
		uint8_t current_client_id[CLIENT_ID_LENGTH];
		for (j = 0; j < CLIENT_ID_LENGTH; j++)
			current_client_id[j] = response_payload[j];
		response_payload += CLIENT_ID_LENGTH + MESSAGE_ID_LENGTH;
		
		message_type = *response_payload;
		response_payload += MESSAGE_TYPE_FIELD_LENGTH;

		uint8_t sizes[4] = { response_payload[0], response_payload[1], 
							response_payload[2], response_payload[3] };
		message_size = *((uint32_t*)sizes);
		response_payload += MESSAGE_SIZE_FIELD_LENGTH;

		string client_name = get_client_name_by_id(all_clients, current_client_id);

		string *symmetric_key = &(*all_clients)[client_name].symmetric_key;
		if (message_type == SEND_SYMMETRIC_KEY_TYPE && *symmetric_key == "")
		{
			print_message(client_name, message_type, message_size, response_payload, symmetric_key);
			string cipher_symmetric_key = "";
			for (j = 0; j < message_size; j++)
				cipher_symmetric_key += response_payload[j];
			*symmetric_key = asymmetric_decrypt(cipher_symmetric_key, &this_client->private_key);
		}
		
		else if (message_type == SEND_TEXT_MESSAGE_TYPE && symmetric_key->length() == SYMMETRIC_KEY_LENGTH)
			print_message(client_name, message_type, message_size, response_payload, symmetric_key);
		
		else if (message_type == ASK_SYMMETRIC_KEY_TYPE)
			print_message(client_name, message_type, message_size, response_payload, symmetric_key);

		response_payload += message_size;
		i += CLIENT_ID_LENGTH + MESSAGE_ID_LENGTH + MESSAGE_TYPE_FIELD_LENGTH;
		i += MESSAGE_SIZE_FIELD_LENGTH + message_size;
	}
}

void handle_message_sent(uint8_t* response_payload, map<string, ClientInfo> *all_clients)
{
	uint8_t client_id[CLIENT_ID_LENGTH];
	copy_client_id(client_id, response_payload);
	response_payload += CLIENT_ID_LENGTH;

	string client_name = get_client_name_by_id(all_clients, client_id);
	LOG("the message was sent successfully to a client with a name: " + client_name);
}

void identify_response(Response* response, uint8_t* response_payload, string* username,
	map<string, ClientInfo>* all_clients, ClientInfo* this_client)
{
	if (response->code == RESPONSE_GENERAL_ERROR)
		error_displayer(RESPONSE_GENERAL_ERROR);

	else if (response->code == RESPONSE_REGISTER_SUCCESS)
		handle_registration(this_client, response_payload, username);

	else if (response->code == RESPONSE_GET_CLIENTS_SUCCESS)
		handle_get_clients(response, all_clients, response_payload);

	else if (response->code == RESPONSE_GET_PUBLIC_KEY_SUCCESS)
		handle_get_public_key(all_clients, response_payload);

	else if (response->code == RESPONSE_PULLING_MESSAGES_SUCCESS)
		handle_pulling_messages(response_payload, response->payload_size, all_clients, this_client);

	else if (response->code == RESPONSE_SENDING_MESSAGE_SUCCESS)
		handle_message_sent(response_payload, all_clients);
}