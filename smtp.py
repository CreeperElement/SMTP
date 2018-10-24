"""
- CS2911 - 0NN
- Fall 2017
- Lab N
- Names:
  - Seth Fenske
  - Angad Singh

A simple email sending program.

Thanks to Trip Horbinski from the Fall 2015 class for providing the password-entering functionality.
"""

# GUI library for password entry
import tkinter as tk

# Socket library
import socket

# SSL/TLS library
import ssl

# base-64 encode/decode
import base64

# Python date/time and timezone modules
import datetime
import time
import pytz
import tzlocal

# Module for reading password from console without echoing it
import getpass

# Modules for some file operations
import os
import mimetypes

# Host name for MSOE (hosted) SMTP server
SMTP_SERVER = 'smtp.office365.com'

# The default port for STARTTLS SMTP servers is 587
SMTP_PORT = 587

# SMTP domain name
SMTP_DOMAINNAME = 'msoe.edu'


def main():
    """Main test method to send an SMTP email message.

    Modify data as needed/desired to test your code,
    but keep the same interface for the smtp_send
    method.
    """
    (username, password) = login_gui()

    message_info = {}
    message_info['To'] = 'fenskesd@msoe.edu'
    message_info['From'] = username
    message_info['Subject'] = 'Yet another test message'
    message_info['Date'] = 'Thu, 9 Oct 2014 23:56:09 +0000'
    message_info['Date'] = get_formatted_date()

    print("message_info =", message_info)

    message_text = 'Test message_info number 6\r\n\r\nAnother line.'

    smtp_send(password, message_info, message_text)


def login_gui():
    """
    Creates a graphical user interface for secure user authorization.

    :return: (email_value, password_value)
        email_value -- The email address as a string.
        password_value -- The password as a string.

    :author: Tripp Horbinski
    """
    gui = tk.Tk()
    gui.title("MSOE Email Client")
    center_gui_on_screen(gui, 370, 120)

    tk.Label(gui, text="Please enter your MSOE credentials below:") \
        .grid(row=0, columnspan=2)
    tk.Label(gui, text="Email Address: ").grid(row=1)
    tk.Label(gui, text="Password:         ").grid(row=2)

    email = tk.StringVar()
    email_input = tk.Entry(gui, textvariable=email)
    email_input.grid(row=1, column=1)

    password = tk.StringVar()
    password_input = tk.Entry(gui, textvariable=password, show='*')
    password_input.grid(row=2, column=1)

    auth_button = tk.Button(gui, text="Authenticate", width=25, command=gui.destroy)
    auth_button.grid(row=3, column=1)

    gui.mainloop()

    email_value = email.get()
    password_value = password.get()

    return email_value, password_value


def center_gui_on_screen(gui, gui_width, gui_height):
    """Centers the graphical user interface on the screen.

    :param gui: The graphical user interface to be centered.
    :param gui_width: The width of the graphical user interface.
    :param gui_height: The height of the graphical user interface.
    :return: The graphical user interface coordinates for the center of the screen.
    :author: Tripp Horbinski
    """
    screen_width = gui.winfo_screenwidth()
    screen_height = gui.winfo_screenheight()
    x_coord = (screen_width / 2) - (gui_width / 2)
    y_coord = (screen_height / 2) - (gui_height / 2)

    return gui.geometry('%dx%d+%d+%d' % (gui_width, gui_height, x_coord, y_coord))

# *** Do not modify code above this line ***

def authenticate(auth_sock, password, message_info):
    """
    Runs through the authentication process.
    :param auth_sock: Secure sock to do authentication
    :param password: User Password
    :param message_info: Dictionary containing "From:"
    :return: None
    """
    send_bytes(auth_sock, b"AUTH LOGIN")
    print(read_line(auth_sock))
    send_base_64(auth_sock, message_info["From"])
    print(read_line(auth_sock))
    send_base_64(auth_sock, password)
    print(read_line(auth_sock))


def smtp_send(password, message_info, message_text):
    """Send a message via SMTP.

    :param password: String containing user password.
    :param message_info: Dictionary with string values for the following keys:
                'To': Recipient address (only one recipient required)
                'From': Sender address
                'Date': Date string for current date/time in SMTP format
                'Subject': Email subject
            Other keys can be added to support other email headers, etc.
    """
    sock = create_socket()
    print(read_line(sock))
    send_bytes(sock, b"EHLO msoe.edu")
    response = read_response(sock)
    for i in response:
        print(i)
    auth_sock = start_tls(sock)
    send_bytes(auth_sock, b"EHLO msoe.edu")
    response = read_response(auth_sock)
    for i in response:
        print(i)

    authenticate(auth_sock, password, message_info)

def start_tls(sock):
    """
    Starts the tls service, and wraps the socket in an encrypted socket
    :param sock: The socket we are using
    :return: Tbe POST tls encrypted socket
    """
    send_bytes(sock, b'STARTTLS')

    response = read_line(sock)
    response_code, response_body = split_at_char(response, b" ", True)
    if response_code != b'220':
        print(response_code)
        raise Exception("Invalid server response to login authentication")
    secure_sock = get_secure_socket(sock)
    return secure_sock


def get_secure_socket(sock):
    """
    Returns a secured socket.
    :param sock: Original socket
    :return: Secured socket
    :author: Seth Fenske
    """
    context = ssl.create_default_context()
    wrapped_socket = context.wrap_socket(sock, server_hostname=SMTP_SERVER)
    return wrapped_socket

def read_line(sock):
    """
    Returns the byte data from a socket until the CRLF characters.
    :param sock: The socket to read data from
    :return: The message in bytes
    :author: Seth Fenske
    """
    message = b''
    second_byte = sock.recv(1)
    first_byte = sock.recv(1)

    while second_byte + first_byte != b'\r\n':
        message += second_byte
        second_byte = first_byte
        first_byte = sock.recv(1)
    return message


def read_response(sock):
    """
    Reads from the socket and returns all the lines of the response
    :param sock: Socket to read from
    :return: A list of all responses
    :author: Seth Fenske
    """
    messages = []
    last_line = read_line(sock)
    messages.append(last_line)
    while line_contains_character(last_line, b'-'):
        last_line = read_line(sock)
        messages.append(last_line)
    return messages

def read_until_character(sock, character):
    """
    Reads data from the socket until
    :param sock: The socket to read from
    :return: The data in bytes up to and not including the character
    :author: Seth Fenske
    """
    last_byte = sock.recv(1)
    message = b''
    while last_byte != character:
        message += last_byte
        last_byte = sock.recv(1)
    return message

def send_bytes(sock, message):
    """
    Sends the message through the socket, adding the line endings
    :param sock: Socket to send data
    :param message: Message to send, without line endings
    :return: None
    :author: Seth Fenske
    """
    print("C: " + (message + b'\r\n').decode("ASCII"))
    sock.sendall(message + b'\r\n')

def send_base_64(sock, message):
    """
    Sends the message in base64 encoding.
    :param sock: The secure sock to use
    :param message: The message to be sent
    :return: None
    """
    send_bytes(sock, base64.b64encode(message.encode("ASCII")))

def split_at_char(message_bytes, character, remove_CRLF):
    """
    Takes a bytestring message as an argument, and splits it at the character specified. If the remove_CRLF is true,
     the last two characters are truncated if they are CRLF.
    :param message_bytes: The message to be split
    :param character: The character to remove
    :param remove_CRLF: Boolean value to determine if the line ends in a CRLF, whether or not to remove it.
    :return: A tuple of each half of the split.
    :author: Seth Fenske
    """
    halves = message_bytes.split(character)
    if b'\r\n' in halves[0] and remove_CRLF:
        return halves(0), halves(1)[0, len(halves(1))-2]
    else:
        return halves[0], halves[1]

def line_contains_character(message, character):
    """
    Checks to see if the supplied message contains the supplied character
    :param message: Message to check
    :param character: The character we are looking for
    :return: A boolean representing whether or not the message contains the character
    :author: Seth Fenske
    """
    current_byte = b""
    message_length = len(message)
    index = 0
    byte_found = False
    while index < message_length and not(byte_found):
        current_byte = message[index: index + 1]
        byte_found = current_byte == character
        index += 1
    return byte_found

def create_socket():
    """
    Returns a new TCP socket.
    :return: A socket to be used to communicate with the SMTP server
    :author: Seth Fenske
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SMTP_SERVER, SMTP_PORT))
    return sock

# ** Do not modify code below this line. **

# Utility functions
# You may use these functions to simplify your code.


def get_formatted_date():
    """Get the current date and time, in a format suitable for an email date header.

    The constant TIMEZONE_NAME should be one of the standard pytz timezone names.
    If you really want to see them all, call the print_all_timezones function.

    tzlocal suggested by http://stackoverflow.com/a/3168394/1048186

    See RFC 5322 for details about what the timezone should be
    https://tools.ietf.org/html/rfc5322

    :return: Formatted current date/time value, as a string.
    """
    zone = tzlocal.get_localzone()
    print("zone =", zone)
    timestamp = datetime.datetime.now(zone)
    timestring = timestamp.strftime('%a, %d %b %Y %H:%M:%S %z')  # Sun, 06 Nov 1994 08:49:37 +0000
    return timestring


def print_all_timezones():
    """ Print all pytz timezone strings. """
    for tz in pytz.all_timezones:
        print(tz)


# You probably won't need the following methods, unless you decide to
# try to handle email attachments or send multi-part messages.
# These advanced capabilities are not required for the lab assignment.


def get_mime_type(file_path):
    """Try to guess the MIME type of a file (resource), given its path (primarily its file extension)

    :param file_path: String containing path to (resource) file, such as './abc.jpg'
    :return: If successful in guessing the MIME type, a string representing the content
             type, such as 'image/jpeg'
             Otherwise, None
    :rtype: int or None
    """

    mime_type_and_encoding = mimetypes.guess_type(file_path)
    mime_type = mime_type_and_encoding[0]
    return mime_type


def get_file_size(file_path):
    """Try to get the size of a file (resource) in bytes, given its path

    :param file_path: String containing path to (resource) file, such as './abc.html'

    :return: If file_path designates a normal file, an integer value representing the the file size in bytes
             Otherwise (no such file, or path is not a file), None
    :rtype: int or None
    """

    # Initially, assume file does not exist
    file_size = None
    if os.path.isfile(file_path):
        file_size = os.stat(file_path).st_size
    return file_size


main()
