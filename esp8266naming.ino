
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <ESP8266mDNS.h>
#include <vector>
#include <list>
#include <string>

const char *ssid = "MySSID";
const char *pass = "MyPassPhrase";

const char *HOSTNAME = "esp8266";

const int TTL = 60;

#define DNS_TYPE_A 1
#define DNS_TYPE_PTR 12
#define DNS_TYPE_AAAA 28
#define DNS_TYPE_NB 32

#define DNS_CLASS_IN 1

struct dns_a_record_t {
  uint32_t addr;
};

struct dns_header_t {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

struct query_t {
  uint16_t upstream_id;
  uint16_t requester_id;
  time_t time;
  uint16_t type;
  std::string name;
};

struct question_t {
  std::string name;
  uint16_t type;
  uint16_t clas;
};

struct answer_t {
  std::string name;
  uint16_t type;
  uint16_t clas;
  uint32_t ttl;
  std::vector<char> data;
};

inline uint16_t read_uint16_be(void const *ptr)
{
  unsigned char const *p = (unsigned char const *)ptr;
  return (p[0] << 8) | p[1];
}

inline uint32_t read_uint32_be(void const *ptr)
{
  unsigned char const *p = (unsigned char const *)ptr;
  return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
}

int decode_name(char const *begin, char const *end, char const *ptr, std::vector<char> *out)
{
  if (begin && ptr && begin <= ptr && ptr < end) {
    char const *start = ptr;
    if ((*ptr & 0xc0) == 0xc0) {
      if (ptr + 1 < end) {
        int o = ((ptr[0] & 0x3f) << 8) | (ptr[1] & 0xff);
        decode_name(begin, end, begin + o, out);
        ptr += 2;
      }
    } else {
      while (ptr < end) {
        int len = *ptr & 0xff;
        ptr++;
        if (len == 0 || len > 63) {
          break;
        }
        if (!out->empty()) {
          out->push_back('.');
        }
        out->insert(out->end(), ptr, ptr + len);
        ptr += len;
      }
    }
    if (ptr < start || ptr > end) {
      ptr = end;
    }
    return ptr - start;
  }
  return 0;
}

int decode_name(char const *begin, char const *end, char const *ptr, std::string *name)
{
  std::vector<char> tmp;
  tmp.reserve(100);
  int n = decode_name(begin, end, ptr, &tmp);
  if (n > 0 && !tmp.empty()) {
    char const *p = &tmp[0];
    *name = std::string(p, p + tmp.size());
    return n;
  }
  return 0;
}

static int parse_question_section(char const *begin, char const *end, char const *ptr, struct question_t *out)
{
  int n = decode_name(begin, end, ptr, &out->name);
  if (n > 0 && !out->name.empty()) {
    char const *start = ptr;
    ptr += n;
    uint16_t tmp[2];
    memcpy(tmp, ptr, 4);
    ptr += 4;
    out->type = read_uint16_be(&tmp[0]);
    out->clas = read_uint16_be(&tmp[1]);
    return ptr - start;
  }
  return 0;
}

void parse_response(char const *begin, char const *end, dns_header_t *header, std::list<question_t> *questions, std::list<answer_t> *answers)
{
  char const *ptr = begin;

  header->id = read_uint16_be(&ptr[0]);
  header->flags = read_uint16_be(&ptr[2]);
  header->qdcount = read_uint16_be(&ptr[4]);
  header->ancount = read_uint16_be(&ptr[6]);
  header->nscount = read_uint16_be(&ptr[8]);
  header->arcount = read_uint16_be(&ptr[10]);
  ptr += 12;

  std::vector<char> res;

  for (int i = 0; i < header->qdcount; i++) {
    question_t q;
    int n = parse_question_section(begin, end, ptr, &q);
    if (n > 0 && !q.name.empty()) {
      ptr += n;
      questions->push_back(q);
    }
  }

  for (int i = 0; i < header->ancount; i++) {
    answer_t a;
    int n = decode_name(begin, end, ptr, &a.name);
    if (n > 0 && !a.name.empty()) {
      ptr += n;
    }
    if (ptr + 10 <= end) {
      uint16_t tmp[5];
      memcpy(tmp, ptr, 10);
      a.type = read_uint16_be(&tmp[0]);
      a.clas = read_uint16_be(&tmp[1]);
      a.ttl = read_uint32_be(&tmp[2]);
      uint16_t rdlen = read_uint16_be(&tmp[4]);
      ptr += 10;
      if (ptr + rdlen <= end) {
        std::list<answer_t>::iterator it = answers->insert(answers->end(), answer_t());
        *it = a;
        it->data.resize(rdlen);
        memcpy(&it->data[0], ptr, rdlen);
        ptr += rdlen;
      }
    }
  }
}

std::string decode_netbios_name(std::string const &name, int *restype)
{
  int n = name.size() / 2;
  if (n > 16) n = 16;
  int i;
  unsigned char tmp[16];
  for (i = 0; i < n; i++) {
    char h = name[i * 2 + 0];
    char l = name[i * 2 + 1];
    if (h >= 'A' && h <= 'P' && l >= 'A' && l <= 'P') {
      unsigned char c = ((h - 'A') << 4) | (l - 'A');
      tmp[i] = c;
    }
  }
  if (i > 1) {
    i--;
    *restype = tmp[i];
    while (i > 0 && isspace(tmp[i - 1])) i--;
    return std::string((char const *)tmp, i);
  }
  *restype = -1;
  return std::string();
}

inline uint16 htons(uint16 v)
{
  unsigned char b = (v >> 8) & 0xff;
  unsigned char a = v & 0xff;
  return (a << 8) | b;
}

inline uint32 htonl(uint32 v)
{
  unsigned char d = (v >> 24) & 0xff;
  unsigned char c = (v >> 16) & 0xff;
  unsigned char b = (v >> 8) & 0xff;
  unsigned char a = v & 0xff;
  return (a << 24) | (b << 16) | (c << 8) | d;
}

void write(std::vector<char> *out, char c)
{
  out->push_back(c);
}

void write(std::vector<char> *out, char const *src, int len)
{
  if (src && len > 0) {
    out->insert(out->end(), src, src + len);
  }
}

void write_us(std::vector<char> *out, uint16_t v)
{
  v = htons(v);
  write(out, (char const *)&v, 2);
}

void write_ul(std::vector<char> *out, uint32_t v)
{
  v = htonl(v);
  write(out, (char const *)&v, 4);
}

void write_name(std::vector<char> *out, std::string const &name)
{
  char const *name_begin = name.c_str();
  char const *name_end = name_begin + name.size();
  char const *srcptr = name_begin;
  while (srcptr < name_end) {
    char const *dot = strchr(srcptr, '.');
    int len = (dot ? dot : name_end) - srcptr;
    if (len < 1 || len > 63) {
      return;
    }
    write(out, (char)len);
    write(out, srcptr, len);
    if (!dot) {
      break;
    }
    srcptr += len + 1;
  }
  write(out, (char)0);
}

static void write_dns_header(std::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount)
{
  uint16_t tmp[6];
  tmp[0] = htons(id);
  tmp[1] = htons(flags);
  tmp[2] = htons(qdcount);
  tmp[3] = htons(ancount);
  tmp[4] = htons(nscount);
  tmp[5] = htons(arcount);
  write(out, (char const *)tmp, 12);
}

void write_dns_question_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas)
{
  write_name(out, name);
  write_us(out, type);
  write_us(out, clas);
}

void write_dns_answer_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, dns_a_record_t const &item)
{
  uint32_t addr = htonl(item.addr);
  write_name(out, name);
  write_us(out, type);
  write_us(out, clas);
  write_ul(out, ttl);
  write_us(out, 4);
  write(out, (char const *)&addr, 4);
}

void write_wins_rr(std::vector<char> *out, std::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t nameflags, dns_a_record_t const &item)
{
  uint32_t addr = htonl(item.addr);
  write_name(out, name);
  write_us(out, type);
  write_us(out, clas);
  write_ul(out, ttl);
  write_us(out, 6);
  write_us(out, nameflags);
  write(out, (char const *)&addr, 4);
}

void make_wins_response(dns_header_t const &header, question_t const &q, dns_a_record_t const &r, std::vector<char> *out)
{
  if (q.type == DNS_TYPE_NB) {
    uint16_t nameflags = 0;
    write_dns_header(out, header.id, 0x8580, 0, 1, 0, 0);
    write_wins_rr(out, q.name, q.type, q.clas, TTL, nameflags, r);
  }
}

bool is_my_name(std::string const &name)
{
  int i;
  for (i = 0; HOSTNAME[i]; i++) {
    if (toupper(HOSTNAME[i] & 0xff) != toupper(name[i] & 0xff)) {
      return false;
    }
  }
  if (name[i] == 0) return true;
  if (stricmp(name.c_str() + i, ".local") == 0) return true;
  return false;
}

uint32_t ipaddr(IPAddress const &a)
{
  return (a[0] << 24) | (a[1] << 16) | (a[2] << 8) | a[3];
}


WiFiUDP udp137;

void processWINS()
{
  WiFiUDP *udp = &udp137;
  char buf[2000];
  int len = udp->parsePacket();
  if (len > 0 && len <= sizeof(buf)) {
    udp->read(buf, len); // read the packet into the buffer
    std::vector<char> res;
    dns_header_t header;
    std::list<question_t> questions;
    std::list<answer_t> answers;
    parse_response(buf, buf + len, &header, &questions, &answers);
    if ((header.flags & 0xf800) == 0x0000) { // standard query
      for (std::list<question_t>::const_iterator it = questions.begin(); it != questions.end(); it++) {
        question_t const &q = *it;
        if (q.clas == DNS_CLASS_IN) {
          if (q.type == DNS_TYPE_PTR) {
            // ignore
          } else {
            std::string name;
            if (q.type == DNS_TYPE_NB) {
              int rt = -1;
              name = decode_netbios_name(q.name, &rt);
              if (rt != 0) {
                continue;
              }
            }
            if (!name.empty()) {
              dns_a_record_t record;
              bool found = false;
              if (is_my_name(name)) {
                record.addr = ipaddr(WiFi.localIP());
                found = true;
              }
              if (found) {
                make_wins_response(header, q, record, &res);
                udp->beginPacket(udp->remoteIP(), udp->remotePort());
                udp->write(&res[0], res.size());
                udp->endPacket();
              }
            }
          }
        }
      }
    }
  }
}

void setup()
{
  Serial.begin(115200);
  Serial.println();
  Serial.println();

  Serial.print("Connecting to ");
  Serial.println(ssid);
  WiFi.begin(ssid, pass);
  
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  
  Serial.println("WiFi connected");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  Serial.println("Starting UDP");
  udp137.begin(137);
  MDNS.begin(HOSTNAME, WiFi.localIP());
}

void loop()
{
  processWINS();
}

