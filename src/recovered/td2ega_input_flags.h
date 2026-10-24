#ifndef TD2EGA_INPUT_FLAGS_H
#define TD2EGA_INPUT_FLAGS_H
#include <stdint.h>
typedef struct td2ega_input_flags {uint16_t word,mask;} td2ega_input_flags;
#define TD2EGA_INPUT_ARITH_FLAGS UINT16_C(0x08d5)
static inline uint16_t td2ega_input_parity(uint16_t v)
{unsigned i,ones=0;for(i=0;i<8;++i)ones+=(v>>i)&1;return (uint16_t)((ones&1)==0);}
static inline td2ega_input_flags td2ega_input_flag_result(td2ega_input_flags f,uint16_t v,unsigned width,uint16_t cf,uint16_t af,uint16_t of,int af_defined,uint16_t choice)
{
    uint16_t sign=(uint16_t)(width==8?0x80:0x8000),bits;
    if(width==8)v&=255;
    bits=(uint16_t)(cf|(td2ega_input_parity(v)<<2)|((af_defined?af:choice)<<4)|((v==0)<<6)|(((v&sign)!=0)<<7)|(of<<11));
    f.word=(uint16_t)((f.word&~TD2EGA_INPUT_ARITH_FLAGS)|bits);
    f.mask=(uint16_t)((f.mask|TD2EGA_INPUT_ARITH_FLAGS)&(af_defined?UINT16_C(0xffff):UINT16_C(0xffef)));return f;
}
static inline td2ega_input_flags td2ega_input_flag_logic(td2ega_input_flags f,uint16_t v,unsigned width,uint16_t choice)
{return td2ega_input_flag_result(f,v,width,0,0,0,0,choice);}
static inline td2ega_input_flags td2ega_input_flag_sub(td2ega_input_flags f,uint16_t a,uint16_t b,unsigned width)
{
    uint16_t v=(uint16_t)(a-b),sign=(uint16_t)(width==8?0x80:0x8000);
    return td2ega_input_flag_result(f,v,width,(uint16_t)(a<b),(uint16_t)(((a^b^v)&0x10)!=0),(uint16_t)(((a^b)&(a^v)&sign)!=0),1,0);
}
static inline td2ega_input_flags td2ega_input_flag_add16(td2ega_input_flags f,uint16_t a,uint16_t b)
{
    uint32_t sum=(uint32_t)a+b;uint16_t v=(uint16_t)sum;
    return td2ega_input_flag_result(f,v,16,(uint16_t)(sum>65535),(uint16_t)(((a^b^v)&0x10)!=0),(uint16_t)(((~(a^b))&(a^v)&0x8000)!=0),1,0);
}
static inline td2ega_input_flags td2ega_input_flag_shl1(td2ega_input_flags f,uint16_t a,uint16_t choice)
{
    uint16_t cf=(uint16_t)(a>>15),v=(uint16_t)(a<<1);
    return td2ega_input_flag_result(f,v,16,cf,0,(uint16_t)((v>>15)^cf),0,choice);
}
#endif
