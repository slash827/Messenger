import sqlite3
from constants import *


# this class creates instances that represent a readable format for the client record in the database
class Client_Record:
    def __init__(self, id, name, public_key, last_seen):
        self.id = id
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen

    def __str__(self):
        return f'client has id: {self.id} and name: {self.name}\nhis public key is: {self.public_key},' \
               f' and last seen: {self.last_seen}'


# this class creates instances that represent a readable format for the message record in the database
class Message_Record:
    def __init__(self, id, to_client, from_client, message_type, content):
        self.id = id
        self.to_client = to_client
        self.from_client = from_client
        self.message_type = message_type
        self.content = content

    def __str__(self):
        return f'message id is: {self.id} and to: {self.to_client}\nwas sent from: {self.from_client},' \
               f' the type is: {self.message_type} and content is:\n{self.content}'


# this class is used to create a single instance that access the DB
class DataBase_Access():
    message_id_counter = 0

    def __init__(self):
        self.db_handler = None
        try:
            # connecting to the DB and suits it to work with byte arrays
            self.db_handler = sqlite3.connect('server.db')
            self.db_handler.text_factory = bytes

            # here is the cursor that executes the SQL commands
            self.cursor = self.db_handler.cursor()
            # now we execute the creation of the tables according to the specification
            self.cursor.executescript(f"""
                CREATE TABLE IF NOT EXISTS 
                    clients(ID varchar(32) NOT NULL PRIMARY KEY,
                            Name varchar({NAME_LENGTH}) NOT NULL,
                            PublicKey varchar({PUBLIC_KEY_LENGTH}) NOT NULL, LastSeen text);
                CREATE TABLE IF NOT EXISTS 
                    messages(ID INTEGER PRIMARY KEY,
                            ToClient varchar(32) NOT NULL, FromClient varchar(32) NOT NULL,
                            Type INT NOT NULL, Content blob);
            """)
            self.db_handler.commit()
        except:
            print('an error has happened while creating the DB')

    def close_db(self):
        self.db_handler.close()

    # returns a Client_Record if exists or else None
    def get_client(self, client_id):
        # gets client_id as a UUID object and searches the client record if exists
        try:
            client_id = client_id.hex()
            statement = """SELECT * FROM clients WHERE ID = ?"""
            task = (client_id,)
            injection_check = self.check_injection(task)

            # if there was a possible injection
            if injection_check == POSSIBLE_INJECTION:
                return POSSIBLE_INJECTION
            query_result = self.cursor.execute(statement, task).fetchall()
            self.db_handler.commit()
        except:
            print(f'an error occurred while trying to get client with id: {client_id}')
            return None

        # if the client doesn't exist in the DB return None
        if not query_result:
            return None

        # if it was found we create a Client Record object and return it
        id, name = query_result[0][0], query_result[0][1]
        public_key, last_seen = query_result[0][2], query_result[0][3]
        client_record = Client_Record(id, name, public_key, last_seen)
        return client_record

    # adds a client record to the DB
    def add_client(self, client_record):
        try:
            statement = '''INSERT INTO clients(ID,Name,PublicKey,LastSeen) VALUES(?,?,?,?)'''
            task = (client_record.id.hex(), client_record.name, client_record.public_key, client_record.last_seen)

            injection_check = self.check_injection((task[1], task[3]))
            if injection_check == POSSIBLE_INJECTION:
                return POSSIBLE_INJECTION

            self.cursor.execute(statement, task)
            self.db_handler.commit()
            return CLIENT_ADDED_SUCCESSFULLY
        except:
            print(f'an error occurred while trying to add client with record:\n{client_record}')
            return ERROR_ADDING_CLIENT

    def get_all_clients_names(self):
        try:
            result = []
            query_result = self.cursor.execute("""SELECT Name FROM clients""").fetchall()
            self.db_handler.commit()
        except:
            print('an error occurred while trying to get all clients names')
            return None

        # here we returns all clients names in a list of strings
        for row in query_result:
            result.append(row[0])
        result = [item.decode("utf-8") for item in result]
        return result

    # returns all clients info except the client that was asking for it
    def get_all_clients_info_except(self, client_id):
        # if the client is not in the database then there is no meaning for the search
        if self.get_client(client_id) is None:
            return None
        try:
            statement = """SELECT ID,Name FROM clients WHERE ID != ?"""
            task = (client_id.hex(),)

            # first we make sure there is no possible injection
            injection_check = self.check_injection(task)
            if injection_check == POSSIBLE_INJECTION:
                return POSSIBLE_INJECTION

            # then execute the query
            query_result = self.cursor.execute(statement, task).fetchall()
            self.db_handler.commit()
        except:
            print(f'an error occurred while trying to get all clients except the one with id: {client_id}')
            return None

        # if it's the only client in the DB
        if query_result is None:
            return []

        # here we decode the client's id and name in a list and returns it
        result = []
        for row in query_result:
            result.append([bytes.fromhex(row[0].decode('utf-8')), row[1]])
        return result

    # returns the client's public key if the client exists or None else
    def get_client_public_key(self, client_id):
        try:
            statement = """SELECT PublicKey FROM clients WHERE ID = ?"""
            task = (client_id.hex(),)
            query_result = self.cursor.execute(statement, task).fetchall()
            self.db_handler.commit()
        except:
            print(f'an error occurred while trying to get the public key of the client with id: {client_id}')
            return None

        # first we check the case in which the client is not in the database
        if not query_result:
            return None
        # if it is, then we return it's public key
        return query_result[0][0]

    # adds a Message record to the DB
    def add_message(self, message: Message_Record):
        try:
            statement = '''INSERT INTO messages(ID,ToClient,FromClient,Type,Content) VALUES(?,?,?,?,?)'''
            task = (self.message_id_counter, message.to_client.hex(), message.from_client.hex(),
                    message.message_type, message.content)

            injection_check = self.check_injection(task[:-1])
            if injection_check == POSSIBLE_INJECTION:
                return POSSIBLE_INJECTION

            self.message_id_counter += 1
            self.cursor.execute(statement, task)
            self.db_handler.commit()
            # we returns the message id so that it could be processed
            return self.message_id_counter
        except:
            print(f'an error occurred while trying to add message with this record: {message}')
            return SQL_GENERAL_ERROR

    # returns a list with all the incoming messages for the client
    def remove_messages_for_client(self, client_id):
        try:
            client_id = client_id.hex()
            # first we retrieve all the message that need to be pulled
            statement = """SELECT * FROM messages WHERE ToClient = ?"""
            task = (client_id,)

            injection_check = self.check_injection(task)
            if injection_check == POSSIBLE_INJECTION:
                return POSSIBLE_INJECTION

            task = (client_id,)
            query_result = self.cursor.execute(statement, task).fetchall()

            # then we delete them from the DB
            statement = """DELETE FROM messages WHERE ToClient = ?"""
            self.cursor.execute(statement, task)
            self.db_handler.commit()
        except:
            print(f'an error occurred while trying to pull messages for client with id: {client_id}')
            return None

        result = []
        for row in query_result:
            message = Message_Record(id=row[0], to_client=bytes.fromhex(row[1].decode()),
                                     from_client=bytes.fromhex(row[2].decode()),
                                     message_type=row[3], content=row[4])
            result.append(message)
        return result

    @staticmethod
    def check_injection(task: tuple):
        problematic_chars = ";'\"!="
        for input_string in task:
            input_string = str(input_string)

            for char in input_string:
                if char in problematic_chars:
                    print(f'that is the problem input: {input_string}')
                    print(f'and the char is: {char}')
                    return POSSIBLE_INJECTION
        # if the check was OK
        return 0


# this is the database object that the other files use to access the DB
database_obj = DataBase_Access()
