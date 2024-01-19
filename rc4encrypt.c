#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction033)(USTRING* Data, USTRING* Key);

void PrintHexArray(const unsigned char* data, size_t length) {
    printf("unsigned char bin[] = {\n");
    for (size_t i = 0; i < length; ++i) {
        printf("0x%02x, ", data[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    printf("\n};\n");
}

void ParseShellcodeString(const char* str, unsigned char* byteArray, size_t* byteArrayLength) {
    const char* pos = str;
    size_t count = 0;

    while (*pos != '\0' && *pos != '\\') pos++;

    while (*pos != '\0') {
        if (*pos == '\\' && *(pos + 1) == 'x') {
            sscanf_s(pos + 2, "%2hhx", &byteArray[count++]);
            pos += 4;
        }
        else {
            pos++;
        }
    }
    *byteArrayLength = count;
}

BOOL Rc4Encrypt(IN PBYTE pRc4Key, IN PBYTE pData, IN DWORD dwRc4KeySize, IN DWORD dwDataSize) {
    NTSTATUS STATUS = NULL;
    USTRING Key = { .Buffer = pRc4Key, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize },
        Data = { .Buffer = pData, .Length = dwDataSize, .MaximumLength = dwDataSize };

    fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

    if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
        printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
        return FALSE;
    }

    return TRUE;
}

void PrintUsage(const char* programName) {
    printf("Usage:\n");
    printf("%s -b <path_to_bin_file> <plaintext_key>\n", programName);
    printf("  Encrypts a binary file with the given key.\n");
    printf("%s -a --shellcode <shellcode_as_hex_string> <plaintext_key>\n", programName);
    printf("  Encrypts shellcode given as a hex string with the given key and prints the result.\n");
    printf("%s -h\n", programName);
    printf("  Displays this help message.\n");
}

void PrintKeyInCFormat(const char* key) {
    printf("\n\n//---------------------------- Key Array ----------------------------\n");
    printf("unsigned char key[] = {\n    ");
    for (size_t i = 0; key[i] != '\0'; ++i) {
        if (i > 0) {
            printf(", ");
        }
        printf("'%c'", key[i]);  // Print each character in the 'key' array
    }
    printf("\n};\n");
    printf("//-------------------------------------------------------------------");
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        printf("\n\n---------------Usage--------------\n\n");
        printf("%s -b <path\\to\\bin\\file> <plaintext key>\n\n", argv[0]);
        printf("or\n\n");
        printf("%s -a --shellcode <shellcode as hex string> <plaintext key>\n\n\n", argv[0]);
        printf("Shellcode Hex Format: \\x03\\x41\\x82..\n");
        printf("\n\n----------------------------------\n\n");
        return -1;
    }

    char* mode = argv[1];
    if (strcmp(mode, "-h") == 0) {
        PrintUsage(argv[0]);
    }
    else if (strcmp(mode, "-b") == 0) {
        // Binary mode
        char* filePath = argv[2];
        char* key = argv[3];
        size_t keyLength = strlen(key);

        FILE* file = fopen(filePath, "rb");
        if (!file) {
            printf("Failed to open binary file.\n");
            return -1;
        }

        fseek(file, 0, SEEK_END);
        size_t fileSize = ftell(file);
        fseek(file, 0, SEEK_SET);

        unsigned char* buffer = malloc(fileSize);
        if (!buffer) {
            printf("Failed to allocate memory for file buffer.\n");
            fclose(file);
            return -1;
        }

        fread(buffer, 1, fileSize, file);
        fclose(file);

        Rc4Encrypt((PBYTE)key, buffer, keyLength, fileSize);

        char encFilePath[260];
        snprintf(encFilePath, sizeof(encFilePath), "enc_%s", filePath);
        FILE* encFile = fopen(encFilePath, "wb");
        if (!encFile) {
            printf("Failed to open file for writing encrypted data.\n");
            free(buffer);
            return -1;
        }

        fwrite(buffer, 1, fileSize, encFile);
        fclose(encFile);
        printf("Encrypted file saved as %s\n", encFilePath);
        PrintKeyInCFormat(argv[3]);

        free(buffer);
    }
    else if (strcmp(mode, "-a") == 0 && argc >= 5 && strcmp(argv[2], "--shellcode") == 0) {
        // Array mode
        char* shellcodeString = argv[3];
        size_t shellcodeLength = strlen(shellcodeString) / 4; // Approximation of length
        unsigned char* shellcode = malloc(shellcodeLength);
        if (!shellcode) {
            printf("Memory allocation failed.\n");
            return -1;
        }
        ParseShellcodeString(shellcodeString, shellcode, &shellcodeLength);

        char* key = argv[4];
        size_t keyLength = strlen(key);

        Rc4Encrypt((PBYTE)key, shellcode, keyLength, shellcodeLength);
        printf("\n//------------------------------------------------------------------------\n");
        printf("//Encrypted shellcode:\n");
        printf("//------------------------------------------------------------------------\n");
        PrintHexArray(shellcode, shellcodeLength);
        PrintKeyInCFormat(argv[4]);
        free(shellcode);
    }
    else {
        printf("Invalid arguments.\n");
        return -1;
    }

    return 0;
}
