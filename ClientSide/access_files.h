#include "request_handler.h"
using namespace std;
int get_address_and_port(string&, string&);
string read_info_file();
void client_info_to_file(string*, ClientInfo*);
void me_info_to_client_info(ClientInfo*, Request*);