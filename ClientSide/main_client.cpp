#include <boost/asio.hpp>
#include <iostream>
#include <string>
#include <map>
#include "connect_to_server.h"

void release_resources(tcp::socket* socket, uint8_t* response_payload)
{
	boost::system::error_code ec;
	socket->shutdown(tcp::socket::shutdown_both, ec);
	socket->close();
	if (response_payload != nullptr)
		delete[] response_payload;
}

int fill_one_request(Connection* connect, map<string, ClientInfo> *all_clients, ClientInfo *this_client, uint8_t* response_payload)
{
	Request request;
	Response response;
	string request_payload = "";
	// if the user is registered we load it's info from the file
	if (is_registered())
		me_info_to_client_info(this_client, &request);

	display_menu();
	// we process the request info with this function
	int identify_result = identify_request_type(&request, &request_payload, this_client, all_clients);
	
	if (identify_result == DISPLAY_ERROR)
		return DISPLAY_ERROR;
	// in case of pressing "0"
	if (identify_result == FINISH_PROGRAM)
		return FINISH_PROGRAM;

	connect_to_server(connect);
	response_payload = send_and_receive(&request, connect->socket, &request_payload, &response);
	identify_response(&response, response_payload, &this_client->name, all_clients, this_client);
	
	return IDENTIFIED_SUCCESSFULLY;
}

void get_client_requests(Connection *connect)
{
	ClientInfo this_client;
	map<string, ClientInfo> all_clients;

	// first we evalute the address and port numbers and make sure they are valid
	int request_result, is_valid = get_address_and_port(connect->address, connect->port);
	if (is_valid == WRONG_ADDRESS || is_valid == WRONG_PORT)
		return;
	do
	{
		uint8_t* response_payload = nullptr;
		request_result = fill_one_request(connect, &all_clients, &this_client, response_payload);
		if (request_result != FINISH_PROGRAM && request_result != DISPLAY_ERROR)
			release_resources(connect->socket, response_payload);
	} 
	while (request_result != FINISH_PROGRAM);
}

int main()
{
	try
	{	
		asio::io_context io_context;
		tcp::socket socket(io_context);
		tcp::resolver resolver(io_context);
		Connection connect = { &io_context, &socket, &resolver };

		get_client_requests(&connect);
	}
	catch (std::exception& e)
	{
		cerr << "an error with the following details has occurred:\n" << e.what() << '\n';
	}
}
