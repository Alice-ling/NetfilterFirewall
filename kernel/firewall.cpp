#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <getopt.h>

#include<sys/types.h> 
#include<sys/stat.h>
#include<stdio.h> 
#include<stdlib.h>
#include <stdbool.h>
#include <cstring>
#include <iostream>
using namespace std;

#define FW_ADD_RULE 0
#define FW_DEL_RULE 1
#define FW_CLEAR_RULE 2

#define FW_CDEV_NAME "./fpNetfilterFirewall"
#define file "./rules.dat"

struct Node{

  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool isPermit;
  bool isLog;
  struct Node *next;          //单链表的指针域
};

//实现string到unsigned int的转换
unsigned int toUInt(string str)
{
	unsigned int result(0);//最大可表示值为4294967296（=2‘32-1）
	//从字符串首位读取到末位（下标由0到str.size() - 1）
	for (int i = str.size()-1;i >= 0;i--)
	{
		unsigned int temp(0),k = str.size() - i - 1;
		//判断是否为数字
		if (isdigit(str[i]))
		{
			//求出数字与零相对位置
			temp = str[i] - '0';
			while (k--)
				temp *= 10;
			result += temp;
		}
		else
			//exit(-1);
			break;
	}
	return result;
}
 








int main(){
    FILE *fp;
    int fd;
    string line;
    char str[100];
    char *p;
    string temp;
    Node item;
    /*open device*/
    /*if((fd=fopen(FW_CDEV_NAME,"wb+"))!=(FILE*)0) {
        printf("openning fpNetfilterFirewall successfully");
    } 
    else{
        printf("Error while openning fpNetfilterFirewall");
   }*/
   fd = open(FW_CDEV_NAME, O_RDWR);
    if(fd <= 0) {
        printf("Error while openning fpNetfilterFirewall");
    }
    /*else {
        statusLabel->setText("Successful openning " + QString(FW_CDEV_NAME));
    }*/

    // config file struct like: sip:dip:sport:dport:protocolnumber:smask:dmask:0:0\n
    // read rules
  
    // read int rules
    if((fp=fopen(file,"rb"))!=(FILE*)0) {
        item.next = NULL;
        while((fgets(str,100,fp))!=(char*)0) {
           //line = string::fromLocal8Bit(file.readLine().data());
           for(int i=0;str[i]!='\0';i++) line[i]=str[i];
           cout<<line;

           //item.sip =  
           p=strtok(str,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.sip=toUInt(temp);
           cout<<item.sip;

           //item.dip = strtok(NULL,":").toUInt();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.dip=toUInt(temp);
           cout<<item.dip;

           //item.sport = strtok(NULL,":").toUShort();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.sport = atoi((char*)temp.c_str());

           //item.dport = strtok(NULL,":").toUShort();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.dport = atoi((char*)temp.c_str());

           //item.protocol = strtok(NULL,":").toUShort();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.protocol = atoi((char*)temp.c_str());

           //item.sMask = strtok(NULL,":").toShort();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.sMask = atoi((char*)temp.c_str());

           //item.dMask = strtok(NULL,":").toShort();
           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           item.dMask = atoi((char*)temp.c_str());



           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           unsigned short permit = atoi((char*)temp.c_str());

           p=strtok(NULL,":");
           for(int i=0;p[i]!='\0';i++) temp[i]=p[i];
           unsigned short log= atoi((char*)temp.c_str());


           if(permit == 1) {
                item.isPermit = true;
           } else {
               item.isPermit = false;
           }

           if(log == 1) {
               item.isLog = true;
               cout<<item.isLog;
           } else {
               item.isLog = false;
           }

        }
        fclose(fp);
    }

    // add rules to table widget, and send to kernel
        ioctl(fd, FW_ADD_RULE, item);
 
    // send to kernel,
    return 0;


}
