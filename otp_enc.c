/**************************************************************** 
* Author: Nicholas Schaffner
* Last Modified: 08/25/20
* Description: This program connects to otp_enc_d and asks it to perform a one-time pad style encryption. This program does 
*               not do the encryption but receives the encrypted text back from otp_enc_d. The syntax for this program is:
*               otp_enc plaintext key port
*               plaintext is the name of a file in the current directory that contains the plaintext to encrypt, key contains
*               the encryption key that will be used to encrypt the text and port is the port that this program should attempt
*               to connect to otp_enc_d on. When this program receives the ciphertext back from otp_enc_d, it will output it
*               to stdout. If this program receives key or plaintext files with any bad characters in them, or the key file is
*               shorter than the plaintext file, it will terminate, send appropriate error text to sterr and set the exit value
*               to 1. This program cannot connect to otp_dec_d. All error text will be output to stderr.
****************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

/* Global variables */
#define BUFFER_SIZE 150000

void error(const char *msg){                                                    /* Error function used for reporting issues */
    perror(msg); 
    exit(0); 
} 

int main(int argc, char *argv[]){
    int socketFD, portNumber, charsWritten, charsRead;
    struct sockaddr_in serverAddress;
    struct hostent* serverHostInfo;
    FILE* myFilePtr;                                                            /* File pointer */
    int plainFileSize = 0;                                                      /* Variable to hold the size of the plaintext file passed in as an argument */
    int keyFileSize = 0;                                                        /* Variable to hold the size of the key file passed in as an argument */
    char* plainText;                                                            /* Char pointer to plaintext characters passed in via argv[1] */                                                          
    char* keyText;                                                              /* Char pointer to key characters passed in via argv[2] */
    int i = 0;
    char buffer[BUFFER_SIZE];                                                   /* Array of pointers to strings */
    
    if (argc < 4){                                                              /* Verify if enough arguments were used. There should be at least 3 arguments accompanying the "otp_enc" command */
        fprintf(stderr,"Not enough arguments.\n"); 
        exit(1);                                                                /* Set the exit value to 1 */
    }

    /* Please note, I utilized the following websites for the next section of my code: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c, https://www.geeksforgeeks.org/fseek-in-c-with-example/, and */
    /* https://www.geeksforgeeks.org/ftell-c-example/ */
    myFilePtr = fopen(argv[1], "r");                                            /* Open a file with the name passed in via argv[1] for reading, and point myFilePtr to the file */
    fseek(myFilePtr, 0, SEEK_END);                                              /* Point myFilePtr to the end of the file so we can see how large the file being passed in is */               
    plainFileSize = ftell(myFilePtr);                                           /* Find the position of myFilePtr in the file with respect to the beginning of the file and assign the integer value returned to fileSize */
    
    plainText = malloc(plainFileSize + 1);                                      /* Allocate a sufficient block of memory for the array of pointers named plainText */
    memset(plainText, '\0', sizeof(plainText));                                 /* Clear out the array before using it */
    
    fseek(myFilePtr, 0, SEEK_SET);                                              /* Point myFilePtr back to the beginning of the file to read in the data from the file */
    fgets(plainText, plainFileSize, myFilePtr);                                 /* Read data from the file into the array pointed to by plainText. I referenced: https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm */

    fclose(myFilePtr);                                                          /* Close the current file stream */

    plainText[strlen(plainText)] = '\0';                                        /* Remove the newline character from the plainText string */

    /* Please note, I utilized the following websites for the next section of my code: https://stackoverflow.com/questions/238603/how-can-i-get-a-files-size-in-c, https://www.geeksforgeeks.org/fseek-in-c-with-example/, and */
    /* https://www.geeksforgeeks.org/ftell-c-example/ */
    myFilePtr = fopen(argv[2], "r");                                            /* Open a file with the name passed in via argv[2] for reading, and point myFilePtr to the file */
    fseek(myFilePtr, 0, SEEK_END);                                              /* Point myFilePtr to the end of the file so we can see how large the file being passed in is */               
    keyFileSize = ftell(myFilePtr);                                             /* Find the position of myFilePtr in the file with respect to the beginning of the file and assign the integer value returned to fileSize */

    keyText = malloc(plainFileSize + 1);                                        /* Allocate sufficient block of memory for array of pointers named keyText. plainFileSize is used bc the key string only needs to be as long as plaintext string */
    memset(keyText, '\0', sizeof(keyText));                                     /* Clear out the array before using it */
    
    fseek(myFilePtr, 0, SEEK_SET);                                              /* Point myFilePtr back to the beginning of the file to read in the data from the file */
    fgets(keyText, plainFileSize, myFilePtr);                                   /* Read data from the file into the array pointed to by keyText. I referenced: https://www.tutorialspoint.com/c_standard_library/c_function_fgets.htm */

    fclose(myFilePtr);                                                          /* Close the current file stream */
 
    keyText[strlen(keyText)] = '\0';                                            /* Remove the newline character from the keyText string */

    if(plainFileSize > keyFileSize){                                            /* If statement to compare the number of characters in the plaintext and keytext file. If plaintext > keytext, report an error and exit program */
        fprintf(stderr, "Error: key %s is too short\n", argv[2]);               /* Print out error message to stderr */           
        free(plainText);                                                        /* Free memory allocated to plainText */
        free(keyText);                                                          /* Free memory allocated to keyText */
        exit(1);                                                                /* Exit the program */
    }

    for(i = 0; i < plainFileSize - 1; i++){                                     /* For loop to verify whether each character in the plainText string is an uppercase letter or the space character */
        if(isalpha(plainText[i]) || plainText[i] == ' '){                       /* If the character is an uppercase letter or a space character, proceed to next character in the string */
            ;
        }
        else{                                                                   /* If the character is not an uppercase letter or a space character, report an error and exit program */                 
            fprintf(stderr, "otp_enc error: input contains bad characters\n");  /* Print out error message to stderr */
            free(plainText);                                                    /* Free memory allocated to plainText */
            free(keyText);                                                      /* Free memory allocated to keyText */
            exit(1);                                                            /* Exit the program */
        }
    }    

    /* Set up the address struct */
    memset((char *)&serverAddress, '\0', sizeof(serverAddress));                /* Clear out the address struct */
     
    portNumber = atoi(argv[3]);                                                 /* Get the port number, convert to an integer from a string */
    serverAddress.sin_family = AF_INET;                                         /* Create a network-capable socket */
    serverAddress.sin_port = htons(portNumber);                                 /* Store the port number */
    serverHostInfo = gethostbyname("localhost");                                /* Convert the machine name into a special form of address */
    
    if (serverHostInfo == NULL){
        fprintf(stderr, "CLIENT: ERROR, no such host\n"); 
        exit(0); 
    }

    memcpy((char*)&serverAddress.sin_addr.s_addr, (char*)serverHostInfo->h_addr, serverHostInfo->h_length);     /* Copy in the address */

    /* Set up the socket */
    socketFD = socket(AF_INET, SOCK_STREAM, 0);                                 /* Create the socket */

    if (socketFD < 0){
        error("CLIENT: ERROR opening socket");
    }

    /* Connect to server */
    if (connect(socketFD, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) < 0){    /* Connect socket to address */
        error("CLIENT: ERROR connecting");
    }

    memset(buffer, '\0', sizeof(buffer));                                                   /* Clear out the buffer array */
    charsRead = recv(socketFD, buffer, 6, 0);                                               /* Check to see if this program is trying to connect with otp_dec_d. Read data from the socket, which will be 6 characters */

    if(strncmp(buffer, "DECODE", 6) == 0){                                                  /* Assess if the first 6 characters "DECODE". If so, report an error and exit program. I referenced: https://www.tutorialspoint.com/c_standard_library/c_function_strncmp.htm */
        fprintf(stderr, "Error: could not contact otp_dec_d on port %d\n", portNumber);     /* Print out error message to stderr */
        exit(2);                                                                            /* Exit the program */
    }

    memset(buffer, '\0', sizeof(buffer));                                       /* Clear out the buffer array */

    /* Combine the plaintext string and key string into one string with an idenfiying char inbetween. Please note, I referenced: https://stackoverflow.com/questions/4834811/strcat-concat-a-char-onto-a-string */
    /* I needed to create a string with the identifying character because strcat only works with null-terminated strings */
    strcpy(buffer, plainText);                                                  /* Copy the string in plainText to buffer */
    char dividingChar = '#';                                                    /* This character will be used to identify where the plaintext string ends and the key string begins */
    char charToString[2];                                                       /* Variable to hold the string "#\0" */
    charToString[0] = dividingChar;                                             /* Assign the first character of the string */                                           
    charToString[1] = '\0';                                                     /* Assign the second character of the string */
    strcat(buffer, charToString);                                               /* Concatenate the string copied to buffer with charToString, which will result in character denoting the end of the plaintext string */
    strcat(buffer, keyText);                                                    /* Concatenate the new string copied to buffer with keyText */

    char endingChar = '@';                                                      /* This character will be used to identify where the key string ends */
    char charToEnd[2];                                                          /* Variable to hold the string "@\0" */
    charToEnd[0] = '@';                                                         /* Assign the first character of the string */ 
    charToEnd[1] = '\0';                                                        /* Assign the second character of the string */
    strcat(buffer, charToEnd);                                                  /* Concatenate the string copied to buffer with charToEnd, which will result in character denoting the end of the key string */

    /* Send message to server */
    charsWritten = send(socketFD, buffer, strlen(buffer), 0);                   /* Write to the server */

    if (charsWritten < 0){
        error("CLIENT: ERROR writing to socket");
    }
    
    memset(buffer, '\0', sizeof(buffer));                                       /* Clear out the buffer again for reuse */

    char readBuffer[10];                                                        /* Variable to hold the current chunk of characters that are received from the server */
    while(strstr(buffer, "@") == NULL){                                         /* While we have not reached the end of the message being sent by the terminal */
        memset(readBuffer, '\0', sizeof(readBuffer));                           /* Clear out the buffer array */        
        charsRead = recv(socketFD, readBuffer, sizeof(readBuffer) - 1, 0);      /* Read the server's message from the socket */
        strcat(buffer, readBuffer);                                             /* Concatenate the string copied to buffer with the string received from the server */                                   
        if(charsRead == -1){                                                    /* Check for errors */
            break;
        }
        if(charsRead == 0){
            break;
        }
    }
    int terminalLocation = strstr(buffer, "@") - buffer;                        /* Find the end of the string */
    buffer[terminalLocation] = '\0';                                            /* Replace the "@" character with a null terminator */

    printf("%s\n", buffer);                                                     /* Print the string to stdout */

    close(socketFD);                                                            /* Close the socket */

    free(plainText);                                                            /* Free memory allocated to plainText */
    free(keyText);                                                              /* Free memory allocated to keyText */

    return 0;
}
