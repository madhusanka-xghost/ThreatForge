/*
Author: Madhusankha Nayanajith
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h> // for hash process
#include <curl/curl.h>   // for networking
#include "cJSON.h"       // for read the server response

#define HASH_READ_BUFFER 8192

// Bucket for libcurl to capture the server's reply
struct MemoryStruct
{
    char *memory;
    size_t size;
};

// The CallBack for libcurl to fill the bucket
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL)
    {
        printf("Error: Not enough memory.\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// Help Menu
void print_usage(char *program_name)
{
    fprintf(stderr, "Usage: %s -f <filename> -k <apikey>\n", program_name);
    fprintf(stderr, " -f,   --file      Path to the file to scan.\n");
    fprintf(stderr, " -k    --key       Your VirusTotal API key.\n");
    fprintf(stderr, " -h    --help      Show this help menu.\n");
}

// banner section
void print_banner()
{

    // set the blue color
    printf("\033[1;36m\n");

    // Print the ASCII Art, line by line
    // We must use "\\" to print a single "\"

    printf("$$$$$$$$\\ $$\\                                         $$\\        $$$$$$$$\\                                       \n");
    printf("\\__$$  __|$$ |                                         $$ |        $$  _____|                                      \n");
    printf("   $$ |   $$$$$$$\\   $$$$$$\\   $$$$$$\\   $$$$$$\\ $$$$$$\\     $$ |        $$ |    $$$$$$\\   $$$$$$\\   $$$$$$\\   $$$$$$\\ \n");
    printf("   $$ |   $$  __$$\\ $$  __$$\\ $$  __$$\\  \\____$$\\\\_$$  _|     $$$$$$\\    $$$$$\\  $$  __$$\\ $$  __$$\\ $$  __$$\\ $$  __$$\\\n");
    printf("   $$ |   $$ |  $$ |$$ |  \\__|$$$$$$$$ | $$$$$$$ | $$ |       $$  __|    $$  __| $$ /  $$ |$$ |  \\__|$$ /  $$ |$$$$$$$$ |\n");
    printf("   $$ |   $$ |  $$ |$$ |      $$   ____|$$  __$$ | $$ |$$\\    $$ |       $$ |    $$ |  $$ |$$ |      $$ |  $$ |$$   ____|\n");
    printf("   $$ |   $$ |  $$ |$$ |      \\$$$$$$$\\ \\$$$$$$$ | \\$$$$  |   $$ |       $$ |    \\$$$$$$  |$$ |      \\$$$$$$$ |\\$$$$$$$\\\n");
    printf("   \\__|   \\__|  \\__|\\__|       \\_______| \\_______|  \\____/    \\__|       \\__|     \\______/ \\__|       \\____$$ | \\_______|\n");
    printf("                                                                                                    $$\\  $$ |        \n");
    printf("                                                                                                    \\$$$$$$  |        \n");
    printf("                                                                                                     \\______/         \n");
    printf("\n=================================================================================================================\n");

    printf("\033[1;32m\n"); // Green
    printf("                         Malicious File Scanner v1.0 - @dev xghost\n");
    printf("\033[1;36m\n"); // Change back to blue

    printf("=================================================================================================================\n\n");

    printf("\033[0m\n");
    // Force the text to print before any other output
    // fflush(stdout);
}

int main(int argc, char *argv[])
{

    print_banner(); // print the banner

    char *filename = NULL;
    char *api_key = NULL;

    for (int i = 1; i < argc; i++)
    {
        // check for -f or --file
        if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0)
        {
            if (i + 1 < argc)
            {
                filename = argv[i + 1];
                i++; // skip the filename
            }
            else
            {
                fprintf(stderr, "Error: Missing filename after %s\n", argv[i]);
                print_usage(argv[0]);
                exit(1);
            }
        }
        // check for -k or --key
        else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--key") == 0)
        {
            if (i + 1 < argc)
            {
                api_key = argv[i + 1];
                i++; // skip the key
            }
            else
            {
                fprintf(stderr, "Error: Missing API key after %s\n", argv[i]);
                print_usage(argv[0]);
                exit(1);
            }
        }

        // check for -h or --help
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            print_usage(argv[0]);
            exit(0);
        }
    }
    // Check if we found both arguments
    if (filename == NULL || api_key == NULL)
    {
        if (argc > 1)
        {
            fprintf(stderr, "Error: Both file and API key are required.\n");
        }
        print_usage(argv[0]);
        exit(1);
    }

    // HASH the file (Using OpenSSL)

    FILE *file = fopen(filename, "rb"); // "rb" = Read Binary
    if (file == NULL)
    {
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        exit(1);
    }

    printf("Scanning file: %s\n", filename);

    // 1. Initialize the openSSL hashing
    SHA256_CTX sha256_context;
    SHA256_Init(&sha256_context);

    // Feed the file in chunks
    unsigned char buffer[HASH_READ_BUFFER];
    size_t bytes_read = 0;
    while ((bytes_read = fread(buffer, 1, HASH_READ_BUFFER, file)))
    {
        SHA256_Update(&sha256_context, buffer, bytes_read);
    }
    fclose(file); // close the file

    // Get the final hash value (32 bytes)
    unsigned char hash_bytes[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash_bytes, &sha256_context); // parameters are swapped!

    // Convert the 32-byte hash to a 64-character string
    char hash_string[65]; // 64 chars + 1 null terminator
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(&hash_string[i * 2], "%02x", hash_bytes[i]);
    }
    hash_string[64] = 0;

    printf("File Hash: %s\n", hash_string);

    // VirusTotal API (Using libcurl)

    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk; // Our bucket
    chunk.memory = malloc(1);
    chunk.size = 0;

    // Build the URL to call
    char url_buffer[256];
    sprintf(url_buffer, "https://www.virustotal.com/api/v3/files/%s", hash_string);
    printf("Contacting VirusTotal at: %s\n", url_buffer);

    // Build the Header string with our API key
    char header_buffer[256];
    sprintf(header_buffer, "x-apikey: %s", api_key);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, header_buffer);

    // Initialize libcurl
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl)
    {
        // Set all our options for the request
        curl_easy_setopt(curl, CURLOPT_URL, url_buffer);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L); // Follow redirects

        // Set the callback function and bucket
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);

        // Add our API key to the header
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_CAINFO, "curl-ca-bundle.crt");
        // Use the default SSL certificates
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

        // Make the request
        res = curl_easy_perform(curl);

        // Parse the JSON and Print Report

        if (res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }
        else
        {
            printf("\033[1;34m");
            printf("\n\n--- Scan Report ---\n");
            printf("\033[0m\n");

            // Parse the entire JSON string
            cJSON *json = cJSON_Parse(chunk.memory);

            if (json == NULL)
            {
                fprintf(stderr, "Error: Failed to parse JSON.\n");
            }
            else
            {
                // Navigate to the data object
                const cJSON *data = cJSON_GetObjectItemCaseSensitive(json, "data");

                // Navigate to the attributes object
                const cJSON *attributes = cJSON_GetObjectItemCaseSensitive(data, "attributes");

                // Navigate to the last_analysis_stats object
                const cJSON *stats = cJSON_GetObjectItemCaseSensitive(attributes, "last_analysis_stats");

                if (stats == NULL)
                {
                    // This can happen if the file is new and has no stats yet
                    printf("Result: Could not find analysis stats. \n");
                }
                else
                {
                    // filter the json report
                    const cJSON *malicious = cJSON_GetObjectItemCaseSensitive(stats, "malicious");
                    const cJSON *suspicious = cJSON_GetObjectItemCaseSensitive(stats, "suspicious");
                    const cJSON *undetected = cJSON_GetObjectItemCaseSensitive(stats, "undetected");

                    // Print the report
                    printf("Result: \n");
                    printf("\033[1;31m");
                    printf("  Malicious:   %d\n", malicious->valueint);
                    printf("\033[1;33m");
                    printf("  Suspicious:  %d\n", suspicious->valueint);
                    printf("\033[1;32m");
                    printf("  Undetected:  %d\n", undetected->valueint);

                    printf("\033[1;35m\n");
                    printf("\n[dev-msg] Threat Forge| crafted by Xghost @2025\n\n");
                    printf("\033[0m\n");
                }

                // Clean up the cJSON object
                cJSON_Delete(json);
            }
        }

        // Cleanup the libcurl
        curl_easy_cleanup(curl);
        free(chunk.memory);
        curl_slist_free_all(headers);
    }

    // cleanup globally
    curl_global_cleanup();

    return 0;
}