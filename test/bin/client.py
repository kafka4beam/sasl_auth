from scramp import ScramClient
import base64
import sys

def get_user_input(prompt):
    """ Helper function to get user input and strip any extra whitespace. """
    return input(prompt).strip()

def main():
    # Check if all required arguments are provided
    if len(sys.argv) != 4:
        print("Usage: python script.py <username> <password> <algorithm>")
        sys.exit(1)

    # Unpack command line arguments
    _, username, password, mec = sys.argv

    # Create client
    client = ScramClient([mec], username, password)

    # Generate the first client message
    client_first_message = client.get_client_first()
    print(client_first_message)

    # Simulate receiving server's first message from user input
    server_first_message = get_user_input("")
    if(server_first_message == 'stop'):
        exit()

    # Set server first message
    client.set_server_first(server_first_message)

    # Process server's first message and get the final client message
    client_final_message = client.get_client_final()
    print(client_final_message)

    # Simulate receiving server's final message from user input
    server_final_message = get_user_input("")
    if(server_final_message == 'stop'):
        exit()

    # Set server final message
    client.set_server_final(server_final_message)

    print("AUTH OK")

if __name__ == "__main__":
    main()
