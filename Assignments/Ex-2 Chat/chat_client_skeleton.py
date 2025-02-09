import socket
import select
import msvcrt
# NAME <name> will set name. Server will reply error if duplicate
# GET_NAMES will get all names
# MSG <NAME> <message> will send message to client name or to broadcast
# BLOCK <name> will block a user from sending messages to the client who sent the block command
# EXIT will close client


my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
my_socket.connect(("127.0.0.1", 8888))
print("Enter commands\n")
msg = ""
while msg != "EXIT":
    rlist, wlist, xlist = select.select([my_socket], [], [], 0.2)
    if rlist:
        #
    if msvcrt.kbhit():
        #

my_socket.close()

