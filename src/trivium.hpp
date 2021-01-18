#include <iostream>
#include <stdlib.h>
#include <time.h>
using namespace std;
class trivium{
private :
    unsigned short *a,*b,*c; // arrays in binary
    int sa,sb,sc;
    unsigned int add(unsigned short a,unsigned short b){//xor
        if(a==b)
            return 0;
        return 1;
    }
    unsigned int mul(unsigned short a,unsigned short b){//and
        if((a==1)&&(b==1))
            return 1;
        return 0;
    }
    void byteshift(int r){// where r=1 or 2 or 3
        switch(r){
            case 1:
                for(int i=sa-1; i>0;i--){
                    a[i]=a[i-1];
                }
                break;
            case 2:
                for(int i=sb-1; i>0;i--){
                    b[i]=b[i-1];
                }
                break;
            case 3:
                for(int i=sc-1; i>0;i--){
                    c[i]=c[i-1];
                }
                break;
            default:
                break;
        };
    }
public:
    trivium(unsigned short * key,unsigned short * iv){ // initialization of internal states
        sa=93;
        sb=84;
        sc=111;
        a=new unsigned short[sa];
        b=new unsigned short[sb];
        c=new unsigned short[sa];
        for( int i=0; i<sa;i++){
            a[i]=0;
        }
        for( int i=0; i<sb;i++){
            b[i]=0;
        }
        for( int i=0; i<sc;i++){
            c[i]=0;
        }
        c[110]=1;
        c[109]=1;
        c[108]=1;
        for(int i=0;i<80;i++){
            a[i]=key[i];
            b[i]=iv[i];
        }
        unsigned short t1,t2,t3;
        for(int i=0;i<1152;i++){// 4 full cycles try adjusting here the indexs by -1 to start from zero incase of errors
            t1=mul(a[90],a[91]);
            t1=add(t1,a[65]);
            t1=add(t1,a[92]);
            t1=add(t1,b[77]);//------------------------------------------
            t2=mul(b[81],b[82]);
            t2=add(t2,b[68]);
            t2=add(t2,b[83]);
            t2=add(t2,c[86]);//------------------------------------------
            t3=mul(c[108],c[109]);
            t3=add(t3,c[65]);
            t3=add(t3,c[110]);
            t3=add(t3,a[68]);//------------------------------------------
            byteshift(1);
            byteshift(2);
            byteshift(3);//------------------------------------------
            a[0]=t3;
            b[0]=t1;
            c[0]=t2;
        }
        cout<<"Initialization of internal states complete\n";
    }
    void display(){
        cout<<"Register A :\n";
        for(int i=0;i<sa;i++){
            cout<<a[i];
        }
        cout<<endl;
        cout<<"Register B :\n";
        for(int i=0;i<sb;i++){
            cout<<b[i];
        }
        cout<<endl;
        cout<<"Register C :\n";
        for(int i=0;i<sc;i++){
            cout<<c[i];
        }
        cout<<endl;
    }
    unsigned short* generatenbitstream(int n){
        unsigned short * ptr=new unsigned short[n];
        unsigned short t1,t2,t3,z;
        for(int i=0;i<n;i++){
            t1=add(a[65],a[92]);
            t2=add(b[68],b[83]);
            t3=add(c[65],c[110]);
            z=add(add(t1,t2),t3);// si
            t1=add(t1,b[77]);
            t1=add(t1,mul(a[90],a[91]));
            t2=add(t2,c[88]);
            t2=add(t2,mul(b[81],b[82]));
            t3=add(t3,a[68]);
            t3=add(t3,mul(c[108],c[109]));
            byteshift(1);
            byteshift(2);
            byteshift(3);
            a[0]=t3;
            b[0]=t1;
            c[0]=t2;
            ptr[i]=z;
        }
        return ptr;
    }
    unsigned short * encrypt(unsigned short * stream,unsigned short * text,int len){
        unsigned short * cipher=new unsigned short[len];
        for( int i=0;i<len;i++){
            cipher[i]=add(stream[i],text[i]);
        }
        return cipher;
    }
    unsigned short * decrypt(unsigned short * stream,unsigned short * text,int len){
        return encrypt(stream,text,len);
    }
    ~trivium(){
        delete[] a;
        delete[] b;
        delete[] c;
    }
};