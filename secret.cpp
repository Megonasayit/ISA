/* 
 * @author Richard Hrmo, xhrmor00
 * ISA PROJEKT - "Přenos souboru skrz skrytý kanál"
 */

#include <unistd.h>
#include <string.h>
#include <fstream>
#include <openssl/aes.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <vector>
#include <pcap.h>
#include <netinet/ether.h>
#include <sys/poll.h>

/*
 * namespace
 */
using namespace std;
/*
 * numeric constants
 */
#define FILENAME_MAX_VALUE 100
#define MTU 1500
#define MAX_DATA_LEN 1200
#define IP_HEADER_MAX_SIZE 60
#define MAX_DATA_ENCRYPT 16
#define SLL_HEADER_LEN 16
#define ETHERNET_ADDR_LEN 6
#define DATASIZE 4
#define SECRET_CODE 23034
struct secret
{
    uint16_t code;
};

/*
 * global variables
 */
vector<char> global_data;
int global_size = 0;
char global_filename[100];
int global_filename_size = 1;
int global_filesize = 1;
int global_oversize = 0;
int global_packet_counter = 0;

/*
 * reads file and returns it in char *
 *
 * ifstream &file   - file to read from
 * int *datasize    - stores size of file
 */
const char *read_from_file(ifstream &file, int *datasize)
{
    file.seekg(0, file.end);
    int lenght = file.tellg();
    file.seekg(0, file.beg);
    char *buffer = new char[lenght];
    file.read(buffer, lenght);
    const char *ret = buffer;
    global_filesize = lenght;
    *datasize = lenght;
    return ret;
}

/*
 * writes given char * into file
 *
 * char *name_of_file   - name of file
 * const char *writeout - char * that will be written into file
 * int size             - maximum characters to write
 * bool append          - true for appending at the end of file, false to overwrite file
 */
void write_to_file(char *name_of_file, const char *writeout, int size, bool append)
{
    ofstream file;
    if (append)
        file.open(name_of_file, ios::binary | ios_base::app);
    else
        file.open(name_of_file, ios::binary);
    file.write(writeout, size);
    file.close();
}

/*
 * decrypts data of file with key "xhrmor00" and returns char*
 *
 * ifstream &file - file to read and decrypt data from
 */
vector<char> decrypt_data(ifstream &file)
{
    AES_KEY key_decrypt;
    unsigned char *out;
    vector<char> output;
    file.open(global_filename, ios::binary);
    int datasize;
    const char *to_decrypt = read_from_file(file, &datasize);
    AES_set_decrypt_key((const unsigned char *)"xhrmor00", 128, &key_decrypt);
    out = (unsigned char *)calloc(MAX_DATA_ENCRYPT + (AES_BLOCK_SIZE % MAX_DATA_ENCRYPT), 1);
    while (datasize > MAX_DATA_ENCRYPT)
    {

        AES_decrypt((unsigned char *)to_decrypt, out, &key_decrypt);
        to_decrypt += MAX_DATA_ENCRYPT;
        datasize -= MAX_DATA_ENCRYPT;
        output.insert(output.end(), out, out + MAX_DATA_ENCRYPT);
        memset(out, 0, sizeof(out));
    }
    free(out);
    if (datasize > 0)
    {
        out = (unsigned char *)calloc(datasize + (AES_BLOCK_SIZE % datasize), 1);
        AES_decrypt((unsigned char *)to_decrypt, out, &key_decrypt);
        output.insert(output.end(), out, out + MAX_DATA_ENCRYPT);
        free(out);
    }
    file.close();
    return output;
}

/*
 * encrypts data of file with key "xhrmor00" and returns char*
 *
 * ifstream &file - file to read and encrypt data from
 */
vector<char> encrypt_data(ifstream &file)
{
    unsigned char *out;
    vector<char> output;
    int datalenght;
    const char *data_from_file = read_from_file(file, &datalenght);
    AES_KEY key_encrypt;
    AES_set_encrypt_key((const unsigned char *)"xhrmor00", 128, &key_encrypt);

    out = (unsigned char *)calloc(MAX_DATA_ENCRYPT + (AES_BLOCK_SIZE % MAX_DATA_ENCRYPT), 1);
    while (datalenght > MAX_DATA_ENCRYPT)
    {
        unsigned char *to_encrypt = (unsigned char *)data_from_file;
        AES_encrypt(to_encrypt, out, &key_encrypt);
        data_from_file += MAX_DATA_ENCRYPT;
        datalenght -= MAX_DATA_ENCRYPT;
        output.insert(output.end(), out, out + MAX_DATA_ENCRYPT);
        memset(out, 0, sizeof(out));
    }
    free(out);
    if (datalenght > 0)
    {
        global_oversize = 16 - datalenght;
        global_filesize += global_oversize;
        unsigned char *to_encrypt = (unsigned char *)data_from_file;
        out = (unsigned char *)calloc(MAX_DATA_ENCRYPT + (AES_BLOCK_SIZE % MAX_DATA_ENCRYPT), 1);
        AES_encrypt(to_encrypt, out, &key_encrypt);
        output.insert(output.end(), out, out + MAX_DATA_ENCRYPT);
        free(out);
    }
    return output;
}

/*
 * sends data with use of socket to given ip
 *
 * const char *data     - data to be sent
 * int datalen          - size of data
 * char *ip_hostname    - IP or Hostname to send data to
 * const char *filename - name of file for data to be written to
 * bool name            - true if sending first or last packet containing name and info about file, false if sending file data
 */
int send_data(const char *data, int datalen, char *ip_hostname, const char *filename, bool name)
{
    struct pollfd fds[1];

    char *to_send;
    to_send = (char *)calloc(MAX_DATA_LEN + FILENAME_MAX_VALUE + DATASIZE + 4, 1);
    struct addrinfo hints, *serverinfo;
    memset(&hints, 0, sizeof(hints));

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_RAW;

    if (getaddrinfo(ip_hostname, NULL, &hints, &serverinfo) != 0)
    {
        printf("getaddrinfo error\n");
        return 1;
    }

    int prot;
    if (serverinfo->ai_family == AF_INET)
        prot = IPPROTO_ICMP;
    else
        prot = IPPROTO_ICMPV6;
    int sock = socket(serverinfo->ai_family, serverinfo->ai_socktype, prot);
    if (sock == -1)
    {
        printf("sock error\n");
        return 1;
    }

    char packet[MTU];
    memset(&packet, 0, MTU);

    struct icmphdr *icmp_header = (struct icmphdr *)packet;
    icmp_header->code = ICMP_ECHO;
    icmp_header->checksum = 0;
    struct secret *secret_header = (struct secret *)(packet + sizeof(struct icmphdr));
    secret_header->code = SECRET_CODE;
    fds[0].fd = sock;
    fds[0].events = POLLOUT;

    if (name == 0)
    {
        while (datalen > MAX_DATA_LEN)
        {
            //usleep(1); - if server is slower than client uncomment this
            memcpy(to_send, filename, strlen(filename));
            memcpy(to_send + strlen(filename), "1200", DATASIZE);
            memcpy(to_send + strlen(filename) + DATASIZE, "size", 4);
            memcpy(to_send + strlen(filename) + DATASIZE + 4, data, MAX_DATA_LEN);
            memcpy(packet + sizeof(struct icmphdr) + sizeof(struct secret), to_send, MAX_DATA_LEN + strlen(filename) + DATASIZE + 4);
            int poll_error = poll(fds, 1, -1);
            if (poll_error < 0)
            {
                printf("poll error\n");
                return 1;
            }
            if (poll_error == 0)
            {
                printf("poll timeout\n"); // this should be impossible to happen
            }
            int send_to_error = sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secret) + MAX_DATA_LEN + strlen(filename) + DATASIZE + 4, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen);
            if (send_to_error < 0)
            {
                printf("sendto err\n");
                return 1;
            }

            data += MAX_DATA_LEN;
            datalen -= MAX_DATA_LEN;
            memset(to_send, 0, MAX_DATA_LEN + FILENAME_MAX_VALUE + DATASIZE + 4);
        }
        if (datalen > 0)
        {
            char tmp[2];
            tmp[0] = datalen & 0xff;
            tmp[1] = (datalen >> 8) & 0xff;
            memcpy(to_send, filename, strlen(filename));
            memcpy(to_send + strlen(filename), tmp, 2);
            memcpy(to_send + strlen(filename) + 2, "size", 4);
            memcpy(to_send + strlen(filename) + 2 + 4, data, datalen);
            memcpy(packet + sizeof(struct icmphdr) + sizeof(struct secret), to_send, datalen + strlen(filename) + 2 + 4);
            int poll_error = poll(fds, 1, -1);
            if (poll_error < 0)
            {
                printf("poll error\n");
                return 1;
            }
            if (poll_error == 0)
            {
                printf("poll timeout\n"); // this should be impossible to happen
            }
            int send_to_error = sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secret) + datalen + strlen(filename) + 2 + 4, 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen);
            if (send_to_error < 0)
            {
                printf("sendto last socket err\n");
                return 1;
            }
            memset(to_send, 0, MAX_DATA_LEN + FILENAME_MAX_VALUE + DATASIZE + 4);
        }
    }
    else
    {
        memcpy(to_send, "filename: ", 10);
        memcpy(to_send + 10, data, datalen);
        memcpy(to_send + 10 + datalen, "endfilename", 11);
        char tmp = global_oversize;
        memcpy(to_send + 10 + datalen + 11, &tmp, 1);
        memcpy(to_send + 10 + datalen + 11 + 1, "size", 4);
        memcpy(packet + sizeof(struct icmphdr) + sizeof(struct secret), to_send, strlen(to_send));
        int poll_error = poll(fds, 1, -1);
        if (poll_error < 0)
        {
            printf("poll error\n");
            return 1;
        }
        if (poll_error == 0)
        {
            printf("poll timeout\n"); // this should be impossible to happen
        }
        int send_to_error = sendto(sock, packet, sizeof(struct icmphdr) + sizeof(struct secret) + strlen(to_send), 0, (struct sockaddr *)(serverinfo->ai_addr), serverinfo->ai_addrlen);
        if (send_to_error < 0)
        {
            printf("sendto filename err\n");
            return 1;
        }
        memset(to_send, 0, MAX_DATA_LEN + FILENAME_MAX_VALUE + DATASIZE + 4);
    }

    return 0;
}

/*
 * pcap handler that handles incomming data, parses them and at the arrival of last packet decrypts them and writes them into file
 */
void mypcap_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    const struct ether_header *ethernet;
    const struct ip *my_ip;
    const struct icmphdr *icmp;
    const struct secret *secret_header;
    const char *payload;
    u_int size_ip;
    u_int size_icmp;
    u_int size_secret;

    ethernet = (struct ether_header *)(packet + 2);
    if (ethernet->ether_type == 8)
    {
        my_ip = (struct ip *)(packet + SLL_HEADER_LEN);
        size_ip = sizeof(struct ip);
    }
    else
    {
        size_ip = 40;
    }
    icmp = (struct icmphdr *)(packet + size_ip + SLL_HEADER_LEN);
    size_icmp = sizeof(struct icmphdr);
    secret_header = (struct secret *)(packet + size_ip + size_icmp + SLL_HEADER_LEN);
    size_secret = sizeof(struct secret);
    if (secret_header->code != SECRET_CODE)
        return;

    payload = (char *)(packet + SLL_HEADER_LEN + size_ip + size_icmp + size_secret);
    if (!(strncmp("filename: ", payload, 10)))
    {
        const char *start = payload + 10;
        const char *end;

        if (!(strncmp(payload + 10, global_filename, global_filename_size)))
        {
            char *size_of_overload;
            const char *startsize;
            const char *endsize;
            if (end = strstr(start, "endfilename"))
            {
                startsize = end + 11;
                if (endsize = strstr(startsize, "size"))
                {
                    size_of_overload = (char *)malloc(endsize - startsize + 1);
                    memcpy(size_of_overload, startsize, endsize - startsize);
                    size_of_overload[endsize - startsize] = '\0';
                    global_oversize = size_of_overload[0];
                }
            }
            ifstream file;
            write_to_file(global_filename, &global_data[0], global_size, 0);
            vector<char> out = decrypt_data(file);
            const char *data = &out[0];
            write_to_file(global_filename, data, global_filesize - global_oversize, 0);
            memset(global_filename, 0, strlen(global_filename));
            global_filename_size = 1;
            global_oversize = 0;
            global_size = 0;
            global_data.clear();
        }
        else
        {
            if (end = strstr(start, "endfilename"))
            {
                memcpy(global_filename, start, end - start);
                global_filename[end - start] = '\0';
                global_filename_size = end - start;
            }
        }
    }
    else
    {
        if (!(strncmp(global_filename, payload, global_filename_size)))
        {

            payload += global_filename_size;
            const char *startsize = payload;
            const char *endsize;
            char *size_ptr;
            int size;
            if (strncmp(payload, "1200", 4))
            {
                size_ptr = (char *)malloc(2);
                memcpy(size_ptr, startsize, 2);
                size = size_ptr[0] & 0xff;
                int tmp = size_ptr[1] & 0xff;
                size += tmp << 8;
                payload += 6;
            }
            else
            {
                size = 1200;
                payload += 8;
            }
            global_size += size;
            global_data.insert(global_data.end(), payload, payload + size);
        }
    }
}

/*
 * main
 */
int main(int argc, char **argv)
{

    int c;
    const char *filename = NULL;
    char *ip_hostname = NULL;
    int server = 0;

    while ((c = getopt(argc, argv, "r:s:l")) != -1)
    {
        switch (c)
        {
        case 'r':
            filename = optarg;
            break;
        case 's':
            ip_hostname = optarg;
            break;
        case 'l':
            server = 1;
            break;
        case '?':

            break;
        default:
            return 1;
            break;
        }
    }

    if ((filename == NULL || ip_hostname == NULL) && server == 0)
    {
        return 1;
    }

    ifstream file;
    ofstream output_file;
    file.open(filename, ios::binary);

    AES_KEY key_decrypt;

    AES_set_decrypt_key((const unsigned char *)"xhrmor00", 128, &key_decrypt);

    if (server == 0)
    {
        if (file)
        {

            if (send_data(filename, strlen(filename), ip_hostname, filename, 1) != 0)
            {
                return 1;
            }
            vector<char> out = encrypt_data(file);
            const char *data = &out[0];
            if (send_data(data, global_filesize, ip_hostname, filename, 0) != 0)
            {
                return 1;
            }
            if (send_data(filename, strlen(filename), ip_hostname, filename, 1) != 0)
            {
                return 1;
            }
        }
    }
    else
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        bpf_u_int32 netaddr;
        struct bpf_program fp;

        netaddr = 0;

        /*
         * pcap inspired by ISA examples - pcap-filter.c by Matoušek Petr, Ing., Ph.D., M.A.
         */
        if ((handle = pcap_open_live(NULL, 4294967295, 1, 1000, errbuf)) == NULL)
        {
            printf("pcap_open_live() error\n");
            return 1;
        }
        if (pcap_setdirection(handle, PCAP_D_IN) != 0)
        {
            printf("pcap_setdirection() error\n");
            return 1;
        }

        if (pcap_compile(handle, &fp, "icmp or icmp6", 0, netaddr) == -1)
        {
            printf("pcap_compile() error");
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1)
        {
            printf("pcap_setfilter() error");
            return 1;
        }

        if (pcap_loop(handle, 0, mypcap_handler, NULL) == -1)
        {
            printf("pcap_loop() failed");
            return 1;
        }

        pcap_close(handle);
    }
    file.close();
    return 0;
}