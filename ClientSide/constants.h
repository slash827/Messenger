#define LOG(x)  std::cout << x << std::endl

static const bool DEBUG_MODE = true;
// constants unique for client side
static const int CLIENT_VERSION = 1;
static const int IDENTIFIED_SUCCESSFULLY = 0;
static const int PACKED_REGISTRATION = 0;
static const int FINISH_PROGRAM = 100;

// constants for client side errors
static const int FATAL_ERROR = -1;
static const int DISPLAY_ERROR = 500;
static const int TOO_BIG_REQUEST_INPUT = 501;
static const int INVALID_REQUEST_TYPE = 502;
static const int ALREADY_REGISTERED = 503;
static const int TOO_BIG_NAME = 504;
static const int CLIENT_IS_NOT_REGISTERED = 505;
static const int WRONG_CLIENT_ID_LENGTH = 506;
static const int NAME_IS_NOT_IN_DB = 507;
static const int INVALID_PORT_NUMBER = 508;
static const int INVALID_IP_ADDRESS = 509;
static const int REGISTER_ONLY_OPERATION = 510;
static const int WRONG_ADDRESS = 511;
static const int WRONG_PORT = 512;
static const int NO_CLIENTS_IN_THE_SERVER = 513;
static const int ACTION_REQUIRES_SYMMETRIC_CONNECTION = 514;
static const int ACTION_REQUIRES_NON_SYMMETRIC_CONNECTION = 515;

// overflow errors
static const int MENU_MAX_INPUT_LENGTH = 2;

// constants for request codes
static const int CODE_FOR_REGISTER = 100;
static const int CODE_FOR_GET_ALL_CLIENTS = 101;
static const int CODE_FOR_GET_PUBLIC_KEY = 102;
static const int CODE_FOR_SENDING_MESSAGE = 103;
static const int CODE_FOR_PULLING_MESSAGES = 104;

// messages types
static const int ASK_SYMMETRIC_KEY_TYPE = 1;
static const int SEND_SYMMETRIC_KEY_TYPE = 2;
static const int SEND_TEXT_MESSAGE_TYPE = 3;

// constants for response constants
static const int RESPONSE_GENERAL_ERROR = 9000;
static const int RESPONSE_REGISTER_SUCCESS = 1000;
static const int RESPONSE_GET_CLIENTS_SUCCESS = 1001;
static const int RESPONSE_GET_PUBLIC_KEY_SUCCESS = 1002;
static const int RESPONSE_SENDING_MESSAGE_SUCCESS = 1003;
static const int RESPONSE_PULLING_MESSAGES_SUCCESS = 1004;

// positions in the full header
static const int HEADER_CLIENT_ID_POSITION = 0;
static const int HEADER_SERVER_VERSION_POSITION = 1;
static const int HEADER_CODE_POSITION = 2;
static const int HEADER_PAYLOAD_SIZE_FIELD_POSITION = 3;

// positions in the received buffer
static const int PAYLOAD_START_POSITION = 22;

// important lengths
static const int NAME_LENGTH = 255;
static const int PUBLIC_KEY_LENGTH = 160;
static const int SYMMETRIC_KEY_LENGTH = 16;
static const int FULL_HEADER_LENGTH = 22;
static const int RESPONSE_HEADER_LENGTH = 7;
static const int MESSAGE_HEADER_LENGTH = 21;
static const int MESSAGE_ID_LENGTH = 4;
static const int MESSAGE_SIZE_FIELD_LENGTH = 4;
static const int MESSAGE_TYPE_FIELD_LENGTH = 1;
static const int CLIENT_ID_LENGTH = 16;
static const int EMPTY_PAYLOAD_LENGTH = 0;
static const int PORT_MAX_DIGITS = 5;
static const int PORT_MAX_VALUE = 65535;
