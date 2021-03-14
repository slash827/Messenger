#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <boost/algorithm/hex.hpp>
#include "access_files.h"

bool check_port_valid(string port)
{
	// first we make sure that the port represents a valid number with amount of digits between 1 and 5
	if (port.length() > PORT_MAX_DIGITS || port.length() == 0
		|| !std::all_of(port.begin(), port.end(), ::isdigit))
	{
		error_displayer(INVALID_PORT_NUMBER);
		return false;
	}

	// then we need to make sure that this number is in the right range
	int number = std::stoi(port);
	if (number > PORT_MAX_VALUE || number < 1024)
	{
		error_displayer(INVALID_PORT_NUMBER);
		return false;
	}

	return true;
}

bool check_address_valid(string address)
{
	// this function make sure that a given ip address is valid
	string sub_addresses[4];
	unsigned int i = 0, dot_amount = 0, number;
	sub_addresses[0] = "";

	while (i < address.length() && dot_amount <= 3)
	{
		if (address[i] == '.')
		{
			dot_amount++;
			sub_addresses[dot_amount] = "";
		}
		else
			sub_addresses[dot_amount] += address[i];

		if (sub_addresses[dot_amount].length() > 3)
		{
			error_displayer(INVALID_IP_ADDRESS);
			return false;
		}
		i++;
	}

	if (dot_amount != 3)
	{
		error_displayer(INVALID_IP_ADDRESS);
		return false;
	}

	for (i = 0; i <= dot_amount; i++)
	{
		if (!std::all_of(sub_addresses[i].begin(), sub_addresses[i].end(), ::isdigit))
		{
			error_displayer(INVALID_IP_ADDRESS);
			return false;
		}

		number = std::stoi(sub_addresses[i]);
		if (number > 255)
		{
			error_displayer(INVALID_IP_ADDRESS);
			return false;
		}
	}

	return true;
}

int get_address_and_port(string& address, string& port)
{
	// this function reads the ip address and port and then checks their validity
	string fullPath = read_info_file();

	int index = fullPath.find(':');
	int portLength = fullPath.length() - index - 1;
	address = fullPath.substr(0, index);
	port = fullPath.substr(index + 1, portLength);

	if (!check_port_valid(port))
		return WRONG_PORT;

	if (!check_address_valid(address))
		return WRONG_ADDRESS;
	return 0;
}

string read_info_file()
{
	// this function reads the info.me file and returns the content
	string myText;
	ifstream MyReadFile("server.info");

	getline(MyReadFile, myText);
	MyReadFile.close();

	return myText;
}

void client_info_to_file(string* username, ClientInfo* this_client)
{
	// this function takes the client username, id and the private key and stores it in the me.info file
	fstream fs;
	fs.open("me.info", std::ios::out);

	int j = 0;
	while ((*username)[j] != 0)
		fs << (*username)[j++];
	fs << endl;

	string str_client = "";
	int i = 0;
	while (i < CLIENT_ID_LENGTH)
		str_client += this_client->client_id[i++];

	string hex_client_id;
	boost::algorithm::hex(str_client.begin(), str_client.end(), back_inserter(hex_client_id));
	fs << hex_client_id << endl;

	// todo add the line of the encryption from file to client info
	fs << this_client->private_key;
	fs.close();
}

void me_info_to_client_info(ClientInfo *client_info, Request *request)
{
	// this function takes the me.info file and retrieves the client username, id and the private key
	string hex_client_id, byte_string;
	client_info->private_key = "";
	ifstream infile("me.info");
	if (infile.good())
	{
		getline(infile, client_info->name);
		getline(infile, hex_client_id);
		while (!infile.eof())
		{
			char c;
			infile >> c;
			client_info->private_key += c;
		}
	}
	
	boost::algorithm::unhex(hex_client_id.begin(),
						hex_client_id.end(), back_inserter(byte_string));

	for (int i = 0;i < CLIENT_ID_LENGTH; i++)
	{
		request->client_id[i] = (uint8_t)byte_string[i];
		client_info->client_id[i] = (uint8_t)byte_string[i];
	}

	infile.close();
}