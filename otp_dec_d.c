/**************************************************************** 
* Author: Nicholas Schaffner
* Last Modified: 08/25/20
* Description: This program will run in the background as a daemon. Upon execution, it will output an error if it cannot 
*               be run due to a network error, such as the ports being unavailable. Its function is to perform the decoding
*               of the ciphertext file that is sent to it via a key using one-time pad style encryption. Please note that 
*               this program utlizes modulo 27 as the space character is allowed in the ciphertext files. This program will 
*               listen on a particular port/socket, assigned when it first ran. When a connection is made, this program will 
*               receive from otp_dec a ciphertext and a key via the communication socket. A child of this program will then write  
*               back the plaintext to the otp_dec process that it is connected to via the same communication socket. This program 
*               supports up to 5 concurrent socket connections running at the same time. The syntax for this program is:
*               otp_dec_d listening_port
*               The listening_port is the port that this program will listen on and will always be started in the background. 
*               All errors are output to stderr but will not crash or otherwise exit, unless the erros happen when the program
*               is starting up. This program uses "localhost" as the target IP address/host.
****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Global variables */
#define BUFFER_SIZE 150000

void error(const char *msg){                                                    /* Error function used for reporting issues */
    perror(msg); 
    exit(1); 
} 

int main(int argc, char *argv[]){
    int listenSocketFD, establishedConnectionFD, portNumber, charsRead;
    socklen_t sizeOfClientInfo;
    struct sockaddr_in serverAddress, clientAddress;
    int spawnPid = -5;
    char* transmittedPT;                                                        /* Char pointer to plaintext characters passed to server from client */ 
    char* transmittedKT;                                                        /* Char pointer to key characters passed to server from client */ 
    char buffer[BUFFER_SIZE];                                                   /* Array of pointers to strings */
    char* encryptedText;                                                        /* Char pointer to encrypted characters */ 
    int i = 0;
    int childExitMethod = 0;
    
    if (argc < 2){                                                              /* Check usage & args */
        fprintf(stderr,"USAGE: %s port\n", argv[0]); 
        exit(1); 
    }

    /* Set up the address struct for this process (the server) */
    memset((char *)&serverAddress, '\0', sizeof(serverAddress));                /* Clear out the address struct */
     
    portNumber = atoi(argv[1]);                                                 /* Get the port number, convert to an integer from a string */
    serverAddress.sin_family = AF_INET;                                         /* Create a network-capable socket */
    serverAddress.sin_port = htons(portNumber);                                 /* Store the port number */
    serverAddress.sin_addr.s_addr = INADDR_ANY;                                 /* Any address is allowed for connection to this process */
    
    /* Set up the socket */
    listenSocketFD = socket(AF_INET, SOCK_STREAM, 0);                           /* Create the socket */
    
    if (listenSocketFD < 0){                            
        error("ERROR opening socket");
    }
    
    /* Enable the socket to begin listening */
    if (bind(listenSocketFD, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){    /* Connect socket to port */
        error("ERROR on binding");
    }

    listen(listenSocketFD, 5);                                                  /* Flip the socket on - it can now receive up to 5 connections */ 
    
    while(1){
        /* Accept a connection, blocking if one is not available until one connects */
        sizeOfClientInfo = sizeof(clientAddress);                                                                   /* Get the size of the address for the client that will connect */
        establishedConnectionFD = accept(listenSocketFD, (struct sockaddr *)&clientAddress, &sizeOfClientInfo);     /* Accept */
    
        if (establishedConnectionFD < 0){ 
            error("ERROR on accept");
        }

        char decodingChar[] = "DECODE";                                                                             /* String "DECODE" will be sent to the  client program to verify if client is connecting to correct socket */
        charsRead = send(establishedConnectionFD, decodingChar, strlen(decodingChar), 0);                           /* Write to the client */  

        spawnPid = fork();                                                      /* Fork the process */
        switch(spawnPid){                                                       /* Switch statement to assess spawnPid */
            case -1: {                                                          /* If something goes wrong, fork() returns -1 */                                                    
                fprintf(stderr, "Hull Breach!\n");                              /* Inform the user that an error occurred */
                fflush(stdout);                                                 /* Flush out output buffer */
                exit(1);                                                        /* Set the exit status to 1 */
                break;                                                          /* Break out of the switch statement */
            }
            case 0: {                                                           /* In the child process, fork() returns 0 */
                transmittedPT = malloc(sizeof(char)*BUFFER_SIZE);               /* Allocate a sufficient block of memory for transmittedPT */
                transmittedKT = malloc(sizeof(char)*BUFFER_SIZE);               /* Allocate a sufficient block of memory for transmittedKT */

                memset(transmittedPT, '\0', sizeof(transmittedPT));             /* Clear out the array before using it */
                memset(transmittedKT, '\0', sizeof(transmittedKT));             /* Clear out the array before using it */
                memset(buffer, '\0', sizeof(buffer));                           /* Clear out the array before using it */
           
                char readBuffer[10];                                                                    /* Variable to hold the current chunk of characters that are received from the server */
                
                while(strstr(buffer, "@") == NULL){                                                     /* While we have not reached the end of the message being sent by the terminal */
                    memset(readBuffer, '\0', sizeof(readBuffer));                                       /* Clear out the buffer array */ 
                    charsRead = recv(establishedConnectionFD, readBuffer, sizeof(readBuffer) - 1, 0);   /* Read the client's message from the socket */
                    strcat(buffer, readBuffer);                                                         /* Concatenate the string copied to buffer with the string received from the client */
        
                    if(charsRead == -1){                                                                /* Check for errors */
                        break;
                    }

                    if(charsRead == 0){
                        break;
                    }
                }

                int terminalLocation = strstr(buffer, "@") - buffer;            /* Find the end of the string */
                buffer[terminalLocation] = '\0';                                /* Replace the "@" character with a null terminator */

                i = 0;

                while(i < sizeof(buffer) - 1 && buffer[i] != '#'){              /* Search for the character noting the end of the plaintext string and start of the keytext string */
                    i++;                                                        /* Increment i */
                }

                strncpy(transmittedPT, buffer, i);                              /* Copy i amount of characters from buffer to transmitterPT. I utilized: https://www.tutorialspoint.com/c_standard_library/c_function_strncpy.htm */

                int transmittedPTSize = i;                                      /* Variable to hold the size of the plaintext string */
                int transmittedKTStart = i + 1;                                 /* Variable to indicate where the key text string begins in buffer */

                encryptedText = malloc(sizeof(char)*BUFFER_SIZE);               /* Allocate a sufficient block of memory for encryptedText */ 

                memset(encryptedText, '\0', sizeof(encryptedText));             /* Clear out the array before using it */

                int currentPTValue = 0;                                         /* Variable to hold the current plaintext char ASCII value */
                int currentKTValue = 0;                                         /* Variable to hold the current key char ASCII value */
                int encryptedValue = 0;                                         /* Variable to hold the current encrypted char ASCII value */

                for(i = 0; i < transmittedPTSize; i++){                         /* For loop to encypt each character of the plaintext string via the coinciding character of the key string */
                    if(transmittedPT[i] == ' '){                                /* If the plaintext character is a space, reassign it to the '[' character */
                        transmittedPT[i] = '[';
                    }

                    if(buffer[transmittedKTStart + i] == ' '){                  /* If the key character is a space, reassign it to the '[' character */
                        buffer[transmittedKTStart + i] = '[';
                    }

                    currentPTValue = transmittedPT[i] - 65;                     /* Subtract 65 to get all of the plaintext character ASCII values between 0-27 */
                    currentKTValue = buffer[transmittedKTStart + i] - 65;       /* Subtract 65 to get all of the key character ASCII values between 0-27 */ 

                    encryptedValue = (currentPTValue - currentKTValue);         /* Subtract the current key character value from the current plaintext character value. Assign the difference to encryptedValue */

                    if(encryptedValue < 0){                                     /* If the current encrypted value < 0, add 27 */
                        encryptedValue = encryptedValue + 27;
                    }

                    encryptedValue = (encryptedValue + 65);                     /* Add 65 to the encryptedValue to get the character value between 65-91 */

                    if(encryptedValue == 91){                                   /* If the current encryptedValue is 91, reassign it to the 32 (the space character) */
                        encryptedValue = 32;
                    }

                    encryptedText[i] = encryptedValue;                          /* Set the encryptedText[i] equal to the current encryptedValue, which will set exncryptedText[i] equal to its corresponding ASCII character */
                }

                /* Please note, I referenced: https://stackoverflow.com/questions/4834811/strcat-concat-a-char-onto-a-string */
                char endingChar = '@';                                          /* This character will be used to identify where the key string ends */
                char charToEnd[2];                                              /* Variable to hold the string "@\0" */
                charToEnd[0] = '@';                                             /* Assign the first character of the string */ 
                charToEnd[1] = '\0';                                            /* Assign the second character of the string */
                strcat(encryptedText, charToEnd);                               /* Concatenate the string copied to encryptedText with charToEnd, which will result in character denoting the end of the encrypted string */

                /* Send message to client */
                charsRead = send(establishedConnectionFD, encryptedText, strlen(encryptedText), 0);           /* Write to the client */

                if (charsRead < 0){
                        error("CLIENT: ERROR writing to socket");
                }

                close(establishedConnectionFD);                                 /* Close the existing socket which is connected to the client */
                
                free(transmittedPT);                                            /* Free memory allocated to transmittedPT */
                free(transmittedKT);                                            /* Free memory allocated to transmittedKT */
                free(encryptedText);                                            /* Free memory allocated to encryptedText */
                exit(0);
                break;                                                          /* Break out of the switch statement */
            }
            default: {                                                          /* In the parent process, fork() returns the PID of the child process that was just created */
                close(establishedConnectionFD);                                 /* Close the existing socket which is connected to the client */
                break;                                                          /* Break out of the switch statement */ 
            }
        }

        waitpid(-1, &childExitMethod, WNOHANG);                                 /* Check if any process has completed. This will return with 0 if none have */
    }

    close(listenSocketFD);                                                      /* Close the listening socket */
    
    return 0;
}