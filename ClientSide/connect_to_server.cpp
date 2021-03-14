#include <iostream>
#include "connect_to_server.h"

using boost::asio::ip::tcp;
using namespace boost;

void connect_to_server(Connection* connect)
{
	tcp::socket*socket = connect->socket;
	tcp::resolver* resolver = connect->resolver;
	boost::asio::connect(*socket, resolver->resolve(connect->address, connect->port));
}

uint8_t* send_and_receive(Request* req, tcp::socket* socket, string* payload, Response* response)
{
	// first we send the request header
	auto buffer1 = asio::buffer(req, sizeof(*req));
	socket->send(buffer1);

	// then we send the request payload
	unsigned int send_size = payload->length();
	const char* request_payload = payload->c_str();
	unsigned int offset = 0, amount;
	while (send_size > 0)
	{
		request_payload += offset;
		auto buffer2 = asio::buffer(request_payload, send_size);
		amount = socket->send(buffer2);
		offset += amount;
		send_size -= amount;
	}

	// then we receive the response header
	auto buffer3 = asio::buffer(response, sizeof(*response));
	socket->receive(buffer3);

	if (response->payload_size == 0)
		return nullptr;

	// then we receive the response payload
	unsigned int size = (unsigned int)(response->payload_size);
	uint8_t* response_payload = new uint8_t[size + 1];
	offset = 0;
	while (size > 0)
	{
		response_payload += offset;
		auto buffer4 = asio::buffer(response_payload, size);
		amount = socket->receive(buffer4);
		offset += amount;
		size -= amount;
	}
	return response_payload;
}
