#include "constants.h"
using namespace std;
#pragma pack(push, 1)
struct Request
{
	uint8_t client_id[CLIENT_ID_LENGTH] = { 0 };
	uint8_t version;
	uint8_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Response
{
	uint8_t version;
	uint16_t code;
	uint32_t payload_size;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ClientInfo
{
	uint8_t client_id[CLIENT_ID_LENGTH] = { 0 };
	string name = "";
	uint8_t public_key[PUBLIC_KEY_LENGTH] = { 0 };
	string private_key = ""; // relevant only for the current client
	string symmetric_key = ""; // it is not equal to "" iff there is a symmetric conncetion with this client
};
#pragma pack(pop)

uint8_t* get_client_id_by_name(string, map<string, ClientInfo>*);
bool is_registered();
void error_displayer(int);
void display_menu();
int identify_request_type(Request*, string*, ClientInfo*, map<string, ClientInfo>*);