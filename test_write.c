#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <sys/types.h>
#include<stdbool.h>

#define BUFFER_LENGTH 256               ///< The buffer length (crude but fine)
static char receive[BUFFER_LENGTH];     ///< The receive buffer from the LKM

int fd_set_blocking(int* fd)
 {
    /* Save the current flags */
    int flags = fcntl(*fd, F_GETFL, 0);
    if (flags == -1)
        return 0;

    flags &= ~O_NONBLOCK;
    return fcntl(*fd, F_SETFL, flags) != -1;
}
//enp0s3 lo udp 123.123.21.123;enp0s3 lo tcp 123.12.21.122;enp0s3 lo udp 123.123.21.118;

int main(){
   int ret, fd;
   fd_set fdset;
   char stringToSend[BUFFER_LENGTH];
   printf("Starting device test code example...\n");
   fd = open("/dev/if_mirror_char", O_WRONLY);             // Open the device with read/write access
   if (fd < 0){
      perror("Failed to open the device...");
      return errno;
   }
   printf("fd=%d\n",fd);
   fd_set_blocking(&fd);
 
   printf("Type in a short string to send to the kernel module:\n");
   scanf("%[^\n]%*c", stringToSend);                // Read in a string (with spaces)

   if(!strcmp(stringToSend, "1"))
   	goto end;
   printf("Writing message to the device [%s].\n", stringToSend);
   ret = write(fd, stringToSend, strlen(stringToSend)); // Send the string to the LKM
   if (ret < 0){
      perror("Failed to write the message to the device.");
      return errno;
    }
  
end:
  close(fd);
   
 
   printf("End of the program\n");
   return 0;
}
