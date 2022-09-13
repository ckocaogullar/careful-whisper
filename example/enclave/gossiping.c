#include "gossiping.h"
#include "string.h"
#include "mbedtls/platform.h"

// Check if the ID is already in the list of trusted IDs. Return 1 if trusted, return 0 otherwise
void is_trusted(char *id, char **trusted_ids, int num_trusted_ids){
    for(int i=0; i<num_trusted_ids; i++){
        // Trusted
        if(strcmp(trusted_ids[i], id)==0){
        mbedtls_printf("%s is already trusted\n", id);
        return 1;
        } 
    }
    // Not trusted
    mbedtls_printf("%s is not in the list of trusted enclaves\n", id);
}

// Adding the given ID to the list of trusted enclaves
void add_as_trusted(char *id, char **trusted_ids, int *num_trusted_ids){
    mbedtls_printf("Adding to trusted ids\n");
    trusted_ids[*num_trusted_ids] = id;
    *num_trusted_ids += 1;
    mbedtls_printf("Added %s to the list of trusted IDs\n", id);
}