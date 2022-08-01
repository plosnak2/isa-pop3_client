#include <stdio.h>
#include <getopt.h>
#include <string>
#include <iostream>
#include <string.h>
#include <fstream>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <dirent.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

// global variables for handling parameters
std::string server;
bool param_a = false;
std::string auth_file;
bool param_o = false;
std::string out_dir;
bool param_d = false;
bool param_n = false;
bool param_p = false;
std::string port;
bool param_t = false;
bool param_s = false;
bool param_c = false;
std::string certfile;
bool param_C = false;
std::string certaddr;

// other global variables
bool default_verify_paths = false;
std::string username;
std::string password;
BIO *bio;
SSL_CTX *ctx;
int number_of_messages = 0;
std::string message;
std::string response;
int new_messages = 0;

int is_there(char *argv[], int argc, char *param)
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(param, argv[i]) == 0)
        {
            argv[i] = (char *)"";
            return i;
        }
    }
    return -1;
}

void arg_checker(int argc, char *argv[])
{
    int i = 1;
    int num_of_args = 1;
    int answer;

    // checking -a param
    answer = is_there(argv, argc, (char *)"-a");
    if (answer != -1)
    {
        if (answer + 1 < argc)
        {
            auth_file = argv[answer + 1];
            argv[answer + 1] = (char *)"";
            num_of_args += 2;
            param_a = true;
        }
        else
        {
            fprintf(stderr, "Wrong parameters. You must specify -a param.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        fprintf(stderr, "Wrong parameters. You must specify -a param.\n");
        exit(EXIT_FAILURE);
    }

    // checking -o param
    answer = is_there(argv, argc, (char *)"-o");
    if (answer != -1)
    {
        if (answer + 1 < argc)
        {
            out_dir = argv[answer + 1];
            argv[answer + 1] = (char *)"";
            num_of_args += 2;
            param_o = true;
        }
        else
        {
            fprintf(stderr, "Wrong parameters. You must specify -o param.\n");
            exit(EXIT_FAILURE);
        }
    }
    else
    {
        fprintf(stderr, "Wrong parameters. You must specify -o param.\n");
        exit(EXIT_FAILURE);
    }

    //checking -T param
    answer = is_there(argv, argc, (char *)"-T");
    if (answer != -1)
    {
        param_t = true;
        num_of_args++;
    }

    //checking -S param
    answer = is_there(argv, argc, (char *)"-S");
    if (answer != -1)
    {
        param_s = true;
        num_of_args++;
    }

    //checking -d param
    answer = is_there(argv, argc, (char *)"-d");
    if (answer != -1)
    {
        param_d = true;
        num_of_args++;
    }

    //checking -n param
    answer = is_there(argv, argc, (char *)"-n");
    if (answer != -1)
    {
        param_n = true;
        num_of_args++;
    }

    // checking -c param
    answer = is_there(argv, argc, (char *)"-c");
    if (answer != -1)
    {
        if (answer + 1 < argc)
        {
            certfile = argv[answer + 1];
            argv[answer + 1] = (char *)"";
            num_of_args += 2;
            param_c = true;
        }
        else
        {
            fprintf(stderr, "Wrong parameters.\n");
            exit(EXIT_FAILURE);
        }
    }

    // checking -C param
    answer = is_there(argv, argc, (char *)"-C");
    if (answer != -1)
    {
        if (answer + 1 < argc)
        {
            certaddr = argv[answer + 1];
            argv[answer + 1] = (char *)"";
            num_of_args += 2;
            param_C = true;
        }
        else
        {
            fprintf(stderr, "Wrong parameters.\n");
            exit(EXIT_FAILURE);
        }
    }

    // checking -p param
    answer = is_there(argv, argc, (char *)"-p");
    if (answer != -1)
    {
        if (answer + 1 < argc)
        {
            port = argv[answer + 1];
            argv[answer + 1] = (char *)"";
            num_of_args += 2;
            param_p = true;
        }
        else
        {
            fprintf(stderr, "Wrong parameters.\n");
            exit(EXIT_FAILURE);
        }
    }

    // there must be 1 param left for server
    if (argc != num_of_args + 1)
    {
        fprintf(stderr, "Wrong parameters.\n");
        exit(EXIT_FAILURE);
    }

    // finding the server param
    for (int i = 1; i < argc; i++)
    {
        if (strcmp("", argv[i]) == 0)
        {
            continue;
        }
        else
        {
            server = argv[i];
            break;
        }
    }

    // param T cant be combined with param S
    if (param_t && param_s)
    {
        fprintf(stderr, "Wrong parameters. Param T cannot be combined with param S.\n");
        exit(EXIT_FAILURE);
    }

    if (param_c && !(param_s || param_t))
    {
        fprintf(stderr, "Wrong parameters. You can not pass parameter c without parameter S or T.\n");
        exit(EXIT_FAILURE);
    }

    if (param_C && !(param_s || param_t))
    {
        fprintf(stderr, "Wrong parameters. You can not pass parameter C without parameter S or T.\n");
        exit(EXIT_FAILURE);
    }

    if (param_C && param_c)
    {
        fprintf(stderr, "Wrong parameters. Param C cannot be combined with param c.\n");
        exit(EXIT_FAILURE);
    }
}

// additional function for open_auth_file function that compares 2 words and sets username and password
void check_word(char *word1, char *word2)
{
    static int i = 1;

    if (i == 3)
    {
        username = word1;
        i++;
        return;
    }

    if (i == 6)
    {
        password = word1;
        i++;
        return;
    }

    if (strcmp(word1, word2) != 0)
    {
        fprintf(stderr, "Wrong authfile - bad format.\n");
        exit(EXIT_FAILURE);
    }
    i++;
}

// function for openning and storing name and password of USER
void open_auth_file()
{
    FILE *auth_file_ptr;
    char word[200];

    // openning file
    if ((auth_file_ptr = fopen(auth_file.c_str(), "r")) == NULL)
    {
        fprintf(stderr, "Error while openning file for authentication.\n");
        exit(EXIT_FAILURE);
    }

    // scanning word username and password
    fscanf(auth_file_ptr, "%s", word);
    check_word((char *)"username", word);
    fscanf(auth_file_ptr, "%s", word);
    check_word((char *)"=", word);
    fscanf(auth_file_ptr, "%s", word);
    check_word(word, word);
    fscanf(auth_file_ptr, "%s", word);
    check_word((char *)"password", word);
    fscanf(auth_file_ptr, "%s", word);
    check_word((char *)"=", word);
    fscanf(auth_file_ptr, "%s", word);
    check_word(word, word);
}

// reading a response from a server, terminated by CRLF
void read_from_server()
{
    bool read = true;
    int x = 0;
    response.clear();
    size_t termination;

    // reading server response till there is termination CRLF
    while (read)
    {
        char *buff = new char[1024];
        bzero(buff, 1024);
        x = BIO_read(bio, buff, 1024);
        if (x == 0)
        {
            fprintf(stderr, "Error - connection was closed or data are unavailable.\n");
            exit(EXIT_FAILURE);
        }
        else if (x < 0)
        {
            fprintf(stderr, "Error detected - unsuccessful response from server.\n");
            exit(EXIT_FAILURE);
        }
        std::string tmp = buff;
        termination = tmp.find("\r\n");

        // std::find returns max number at failure so if there is CRLF.CRLF then this condition will be true
        if (termination != std::string::npos)
        {
            read = false;
        }
        response += tmp;
    }

    // controlling status of message
    if (strncmp("+OK", response.c_str(), 3) != 0)
    {
        fprintf(stderr, "Server returned -ERR during reading response.\n");
        exit(EXIT_FAILURE);
    }
    return;
}

// function for reading mail after RETR command -> terminated by CRLF.CRLF
void read_retr()
{
    bool read = true;
    int x = 0;
    message.clear();
    size_t termination;
    bool first_line = true;
    // reading email till there is termination CRLF.CRLF
    while (read)
    {
        char *buff = new char[1024];
        bzero(buff, 1024);
        x = BIO_read(bio, buff, 1024);
        if (first_line)
        {
            if (buff[0] == '-')
            {
                fprintf(stderr, "Server returned -ERR during reading retr response.\n");
                exit(EXIT_FAILURE);
            }
        }
        first_line = false;
        if (x == 0)
        {
            fprintf(stderr, "Error - connection was closed or data are unavailable.\n");
            exit(EXIT_FAILURE);
        }
        else if (x < 0)
        {
            fprintf(stderr, "Error detected - unsuccessful response from server.\n");
            exit(EXIT_FAILURE);
        }
        std::string tmp;
        tmp.clear();
        tmp = buff;
        message += tmp;
        termination = message.find("\r\n.\r\n");

        // std::find returns max number at failure so if there is CRLF.CRLF then this condition will be true
        if (termination != std::string::npos)
        {
            read = false;
        }
    }

    // controlling status of message
    if (strncmp("+OK", message.c_str(), 3) != 0)
    {
        fprintf(stderr, "Server returned -ERR during reading mail.\n");
        exit(EXIT_FAILURE);
    }
    return;
}

void write_to_server(const char *message)
{
    if (BIO_write(bio, message, strlen(message)) <= 0)
    {
        fprintf(stderr, "Error while writing to server.\n");
        exit(EXIT_FAILURE);
    }
}

// openning uncrypted connection with the server
void start_uncrypted_connection()
{
    if (!param_p)
    {
        port = "110";
    }

    //concatennating strings to make it hostname:port and connecting to server
    std::string address = server + ":" + port;
    bio = BIO_new_connect(address.c_str());

    if (bio == NULL)
    {
        fprintf(stderr, "Internal error while creating BIO object.\n");
        exit(EXIT_FAILURE);
    }

    if (BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Error while connecting to server.\n");
        exit(EXIT_FAILURE);
    }

    // reading the welcome message from the server
    read_from_server();

    return;
}

void start_stls_connection()
{
    // firstly setting unsecured connection
    SSL *ssl;
    start_uncrypted_connection();
    // sending STLS command to server
    write_to_server("STLS\r\n");
    read_from_server();
    // lincking certifikates for secured connection
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        fprintf(stderr, "Error while setting connection.\n");
        exit(EXIT_FAILURE);
    }
    if (param_c)
    {
        if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL))
        {
            fprintf(stderr, "Error while loading certificates.\n");
            exit(EXIT_FAILURE);
        }
    }
    else if (param_C)
    {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str()))
        {
            fprintf(stderr, "Error while loading certaddr.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (!param_C && !param_c)
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    // https://stackoverflow.com/questions/49132242/openssl-promote-insecure-bio-to-secure-one
    // pushing ssl into existing bio connection
    bio = BIO_push(BIO_new_ssl(ctx, 1), bio);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    // verifying certifikates
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Error while verifying certificates.\n");
        exit(EXIT_FAILURE);
    }
}

// openning crypted connection with the server
void start_crypted_connection()
{
    if (!param_p)
    {
        port = "995";
    }

    //concatennating strings to make it hostname:port and connecting to server
    std::string address = server + ":" + port;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        fprintf(stderr, "Error while setting connection.\n");
        exit(EXIT_FAILURE);
    }
    SSL *ssl;

    // loading certificate params
    if (param_c)
    {
        if (!SSL_CTX_load_verify_locations(ctx, certfile.c_str(), NULL))
        {
            fprintf(stderr, "Error while loading certificates.\n");
            exit(EXIT_FAILURE);
        }
    }
    else if (param_C)
    {
        if (!SSL_CTX_load_verify_locations(ctx, NULL, certaddr.c_str()))
        {
            fprintf(stderr, "Error while loading certaddr.\n");
            exit(EXIT_FAILURE);
        }
    }

    // if user dont specify certificate paramas then i set default verify paths
    if (!param_C && !param_c)
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }

    // setting up secure connection
    bio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, address.c_str());
    if (bio == NULL)
    {
        fprintf(stderr, "Internal error while creating BIO object.\n");
        exit(EXIT_FAILURE);
    }

    if (BIO_do_connect(bio) <= 0)
    {
        fprintf(stderr, "Error while connecting to server.\n");
        exit(EXIT_FAILURE);
    }

    // verifying certificate if its valid
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Error while verifying certificates.\n");
        exit(EXIT_FAILURE);
    }

    read_from_server();
    return;
}

void authenticate_user()
{
    // send USER command to the server
    std::string user_command = "USER " + username + "\r\n";
    write_to_server(user_command.c_str());
    read_from_server();

    // send PASS command to the server
    std::string pass_command = "PASS " + password + "\r\n";
    write_to_server(pass_command.c_str());
    read_from_server();
}

void get_number_of_messages()
{
    write_to_server("STAT\r\n");
    read_from_server();
    // extracting the count of emails from message
    char *arr = strtok((char *)response.c_str(), " ");
    int i = 0;
    // https://www.codingame.com/playgrounds/14213/how-to-play-with-strings-in-c/string-split
    while (arr != NULL)
    {
        if (i == 1)
        {
            number_of_messages = atoi(arr);
            break;
        }
        arr = strtok(NULL, " ");
        i++;
    }
}

// creating file for mail and storing content into the file
void create_file(int i, char *name)
{
    std::ofstream file;
    file.open(out_dir + name);
    message.erase(0, message.find("\n") + 1);
    message.erase(message.find("\r\n.\r\n") + 2, 3);
    while (message.find("\r\n..") != std::string::npos)
    {
        message.erase(message.find("\r\n..") + 2, 1);
    }

    file << message;
    file.close();
}

// function that retrieves every mail from server
void retrieving_messages()
{
    for (int i = 0; i < number_of_messages; i++)
    {
        int number = i + 1;
        std::string command = "RETR " + std::to_string(number) + "\r\n";
        write_to_server(command.c_str());
        read_retr();

        //getting Message-ID from mail and putting it into file that stores every mail ID
        std::string copy = message;
        std::string temp_message;
        if (message.find("Message-ID") != std::string::npos)
        {
            temp_message = copy.erase(0, message.find("Message-ID"));
        }
        else if (message.find("Message-Id") != std::string::npos)
        {
            temp_message = copy.erase(0, message.find("Message-Id"));
        }
        else if (message.find("Message-id") != std::string::npos)
        {
            temp_message = copy.erase(0, message.find("Message-id"));
        }

        temp_message = temp_message.substr(0, temp_message.find("\r\n"));

        // storing mail ID cause that is gonna be name of file
        std::string mail_name = temp_message;
        mail_name.erase(0, 12);
        temp_message = temp_message + "\n";

        // if param -n was set then i have to check if my message ID is already among other message IDs
        if (param_n)
        {
            bool found = false;
            if (access("mail_ids", F_OK) == 0)
            {
                FILE *filer;
                filer = fopen("mail_ids", "r");
                char *buffer = new char[1024];

                if (filer == NULL)
                {
                    fprintf(stderr, "Internal error while openning file with mail IDs.\n");
                    exit(EXIT_FAILURE);
                }
                while (fgets(buffer, 1024, filer))
                {
                    if (strcmp(temp_message.c_str(), buffer) == 0)
                    {
                        found = true;
                    }
                }
                fclose(filer);
            }
            if (found)
            {
                continue;
            }
            else
            {
                new_messages++;
            }
        }

        // writing mails message-ID into file
        FILE *filew;
        filew = fopen("mail_ids", "a");
        if (filew == NULL)
        {
            fprintf(stderr, "Internal error while openning file with mail IDs.\n");
            exit(EXIT_FAILURE);
        }
        fprintf(filew, "%s", temp_message.c_str());
        fclose(filew);

        create_file(i + 1, (char *)mail_name.c_str());
    }
}

// function for validating if outdir is valid directory
void validating_outdir()
{
    char *temp = (char *)out_dir.c_str();
    if (temp[strlen(temp) - 1] != '/')
    {
        out_dir = out_dir + "/";
    }
    DIR *dir = opendir(out_dir.c_str());
    if (!dir)
    {
        fprintf(stderr, "Specified outdir doesnt exist.\n");
        exit(EXIT_FAILURE);
    }
}

// function for closing connection with server via QUIT command
void close_connection()
{
    write_to_server("QUIT\r\n");
    read_from_server();
}

// function for deleting messages from server
void delete_messages()
{
    for (int i = 0; i < number_of_messages; i++)
    {
        int number = i + 1;
        std::string command = "DELE " + std::to_string(number) + "\r\n";
        write_to_server(command.c_str());
        read_from_server();
    }
}

int main(int argc, char *argv[])
{
    arg_checker(argc, argv);
    open_auth_file();

    // initialization functions
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();

    if (param_t)
    {
        start_crypted_connection();
    }
    else if (param_s)
    {
        start_stls_connection();
    }
    else
    {
        start_uncrypted_connection();
    }

    authenticate_user();
    get_number_of_messages();

    validating_outdir();
    retrieving_messages();

    if (param_d)
    {
        delete_messages();
    }
    close_connection();

    if (param_n)
    {
        if (param_d)
        {
            std::cout << "Stiahnute nove spravy: " + std::to_string(new_messages) + " a vymazane: " + std::to_string(number_of_messages) + "\n";
        }
        else
        {
            std::cout << "Stiahnute nove spravy: " + std::to_string(new_messages) + "\n";
        }
    }
    else
    {
        if (param_d)
        {
            std::cout << "Stiahnute spravy a vymazane: " + std::to_string(number_of_messages) + "\n";
        }
        else
        {
            std::cout << "Stiahnute spravy: " + std::to_string(number_of_messages) + "\n";
        }
    }

    if (param_t || param_s)
    {
        SSL_CTX_free(ctx);
    }
    BIO_free_all(bio);

    return 0;
}