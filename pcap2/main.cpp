#include "main.h"

void macCmp(const u_char *packet)
{
    RadiotapHeader *RH = (RadiotapHeader*)(packet);
    int length = RH->length;
    ManagementFrame *MF = (ManagementFrame*)(packet+length);

    int type = MF->frameCtrl.type;
    int subtype = MF->frameCtrl.subType;

    int ToDs = MF->frameCtrl.toDs;
    int FromDs = MF->frameCtrl.fromDs;


    //if(type == 0 && subtype ==0) // Association Request Frame
    //if((ToDs == 0 && FromDs == 1) || (ToDs == 1 && FromDs == 0))
    {
        printf("====================================================\n");
       /* if(ToDs == 0 && FromDs == 1)
        {
            printf("From AP\n");
        }
        else
        {
            printf("To AP\n");
        }*/

        printf("Sequnce  : %d\n", (MF->seq));

        printMac(packet, 1);    //DA
        printMac(packet, 2);    //SA
        printMac(packet, 3);    //BSS ID

        for(int i=0 ; i<6; i++)
        {
            int n = memcmp((char*)&MF->addr2[i], (char*)&MF->addr3[i], 1);
            if(n != 0)
            {
                printf("different\n");
                break;
            }
            if(i==5)
            {
                printf("same\n");
            }
        }
    }
}

void printMac(const u_char *packet, int n)
{
    RadiotapHeader *RH = (RadiotapHeader*)(packet);
    int length = RH->length;
    ManagementFrame *MF = (ManagementFrame*)(packet+length);


    if(n==1)
    {
        printf("Address1 : ");
        for(int i=0; i<6 ;i++)
        {
            if(i==5)
            {
                printf("%02x\n", MF->addr1[i]);
                break;
            }
            printf("%02x-", MF->addr1[i]);
        }
    }
    else if(n==2)
    {
        printf("Address2 : ");
        for(int i=0; i<6 ;i++)
        {
            if(i==5)
            {
                printf("%02x\n", MF->addr2[i]);
                break;
            }
            printf("%02x-", MF->addr2[i]);
        }
    }
    else if(n==3)
    {
        printf("Address3 : ");
        for(int i=0; i<6 ;i++)
        {
            if(i==5)
            {
                printf("%02x\n", MF->addr3[i]);
                break;
            }
            printf("%02x-", MF->addr3[i]);
        }
    }
    else
        printf("Input Error");
}

 int main(int argc, char *argv[])
 {
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */



    dev = "wlan0";
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    /* Grab a packet */
    for(;;)
    {
    int loopStat = pcap_next_ex(handle, &header, &packet);

    switch(loopStat)
        {
            case 1:
            //packet filtering
            //int function(argvs)
            //checkflag = func1(pktDescrpt);
            macCmp(packet);
            case 0:
                continue;//timeout check
            case -1:
                pcap_perror(handle,"Packet data read error");
                break;
            case -2:
                pcap_perror(handle,"Packet data read error");
                break;
        }
    }

    /* And close the session */
    pcap_close(handle);
    return(0);
 }
