import selectors
import socket
import types
import db_access as db
import request_processor as req_p
import response_handler as res_h
from constants import *
import struct


def accept_wrapper(sock, sel):
    # in this function we accept a connection from a client
    conn, addr = sock.accept()  # Should be ready to read
    print('accepted connection from', addr)
    conn.setblocking(False)

    data = types.SimpleNamespace(addr=addr, inb=b'', outb=b'')
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask, sel):
    # in this function we process a request from a client
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        try:
            recv_data = sock.recv(FULL_HEADER_LENGTH)  # Should be ready to read
            payload_size = struct.unpack_from('<I', recv_data, 18)[0]
            if payload_size > 0:
                sock.settimeout(0.1)
                recv_data += sock.recv(1024 - FULL_HEADER_LENGTH)
        except ConnectionResetError:
            return
        except struct.error:
            return
        if recv_data:
            # first we read the request and process it
            result = req_p.request_identify(recv_data)

            # then we check whether it's a big text message (bigger than 1024 bytes of package
            if result[1] == PROCESSING_BIG_TEXT_MESSAGE:
                try:
                    result = req_p.handle_big_packs(result, sock)
                except ConnectionResetError:
                    return

            # then pack the answer and sends it to the client
            packed_result = res_h.pack_result(result)
            data.outb += packed_result
        else:
            print('closing connection to', data.addr)
            sel.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print(f'sending to client : {data.outb}')
            sent = sock.send(data.outb)  # Should be ready to write
            data.outb = data.outb[sent:]
            print('closing connection to', data.addr)
            sel.unregister(sock)
            sock.close()


def main():
    # first we create a database access object so we can manipulate the DB during runtime
    db_obj = db.database_obj

    # here we read the port from the file and assign the ip of our host (localhost)
    with open("port.info", "r") as file:
        port = int(file.read())
    host = "127.0.0.1"

    # then we create a selector and a socket for the server
    sel = selectors.DefaultSelector()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # here we "activate" the server
    sock.bind((host, port))
    sock.listen()
    print('listening on', (host, port))

    # here we "link" the selector to the socket
    sock.setblocking(True)
    sel.register(sock, selectors.EVENT_READ, data=None)

    # this loop ends only when we terminate the program or ConnectionResetError occurred
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj, sel)
            else:
                if service_connection(key, mask, sel) is None:
                    break


if __name__ == '__main__':
    main()
