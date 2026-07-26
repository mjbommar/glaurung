unsigned crc32_step(unsigned crc, unsigned char b){ crc ^= b;
  for(int i=0;i<8;i++) crc = (crc>>1) ^ (0xEDB88320u & (-(crc&1))); return crc; }
unsigned fletcher16(const unsigned char *d,int n){ unsigned s1=0,s2=0;
  for(int i=0;i<n;i++){ s1=(s1+d[i])%255; s2=(s2+s1)%255; } return (s2<<8)|s1; }
