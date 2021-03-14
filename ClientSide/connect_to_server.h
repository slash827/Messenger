#include <boost/asio.hpp>
#include "response_handler.h"
using boost::asio::ip::tcp;
using namespace boost;
using namespace std;
struct Connection
{
	asio::io_context* io_context;
	tcp::socket* socket;
	tcp::resolver* resolver;
	string address = "", port = "";
};
void connect_to_server(Connection*);
uint8_t* send_and_receive(Request*, tcp::socket*, string*, Response*);