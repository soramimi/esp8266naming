
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <ESP8266mDNS.h>
#include <new>

char ssid[] = "MySSID";
char pass[] = "MyPassPhrase";

char HOSTNAME[] = "esp8266";

const int TTL = 60;

//
namespace tiny {
  template <typename T> class vector {
  private:
    size_t capacity;
    size_t count;
    T *array;
  public:
    vector()
      : capacity(0)
      , count(0)
      , array(0)
    {
    }
    vector(vector const &r)
      : capacity(0)
      , count(0)
      , array(0)
    {
      reserve(r.size());
      for (const_iterator it = r.begin(); it != r.end(); it++) {
        push_back(*it);
      }
    }
    ~vector()
    {
      clear();
      delete[] (char *)array;
    }
    void operator = (vector const &r)
    {
      clear();
      reserve(r.size());
      for (const_iterator it = r.begin(); it != r.end(); it++) {
        push_back(*it);
      }
    }
    class const_iterator;
    class iterator {
      friend vector;
      friend const_iterator;
    private:
      T *ptr;
      T *end;
      int compare(iterator const &r) const
      {
        return ptr - r.ptr;
      }
      bool isnull() const
      {
        return !ptr || ptr == end;
      }
    public:
      iterator(T *p, T *end = 0)
        : ptr(p)
        , end(end)
      {
      }
      bool operator == (iterator it) const
      {
        if (isnull() && it.isnull()) return true;
        return compare(it) == 0;
      }
      bool operator != (iterator it) const
      {
        return !operator == (it);
      }
      void operator ++ ()
      {
        if (!isnull()) ptr++;
      }
      void operator ++ (int)
      {
        if (!isnull()) ptr++;
      }
      T &operator * ()
      {
        return *ptr;
      }
      T *operator -> ()
      {
        return ptr;
      }
      iterator operator + (size_t n) const
      {
        return isnull() ? iterator(end, end) : iterator(ptr + n, end);
      }
      iterator operator - (size_t n) const
      {
        return isnull() ? iterator(end, end) : iterator(ptr - n, end);
      }
      bool operator < (iterator const &it) const
      {
        return compare(it) < 0;
      }
      bool operator > (iterator const &it) const
      {
        return compare(it) > 0;
      }
      bool operator <= (iterator const &it) const
      {
        return compare(it) <= 0;
      }
      bool operator >= (iterator const &it) const
      {
        return compare(it) >= 0;
      }
      size_t operator - (iterator const &it) const
      {
        if (!ptr || !it.ptr) return 0;
        return ptr - it.ptr;
      }
    };
    class const_iterator {
      friend vector;
    private:
      T const *ptr;
      T const *end;
      int compare(const_iterator const &r) const
      {
        return ptr - r.ptr;
      }
      bool isnull() const
      {
        return !ptr || ptr == end;
      }
    public:
      const_iterator(T const *p, T const *end = 0)
        : ptr(p)
        , end(end)
      {
      }
      const_iterator(iterator const &it)
        : ptr(it.ptr)
        , end(it.end)
      {
      }
      bool operator == (const_iterator it) const
      {
        if (isnull() && it.isnull()) return true;
        return compare(it) == 0;
      }
      bool operator != (const_iterator it) const
      {
        return !operator == (it);
      }
      void operator ++ ()
      {
        if (!isnull()) ptr++;
      }
      void operator ++ (int)
      {
        if (!isnull()) ptr++;
      }
      T const &operator * () const
      {
        return *ptr;
      }
      T const *operator -> () const
      {
        return ptr;
      }
      iterator operator + (size_t n) const
      {
        return isnull() ? const_iterator(end, end) : const_iterator(ptr + n, end);
      }
      iterator operator - (size_t n) const
      {
        return isnull() ? const_iterator(end, end) : const_iterator(ptr - n, end);
      }
      bool operator < (const_iterator const &it) const
      {
        return compare(it) < 0;
      }
      bool operator > (const_iterator const &it) const
      {
        return compare(it) > 0;
      }
      bool operator <= (const_iterator const &it) const
      {
        return compare(it) <= 0;
      }
      bool operator >= (const_iterator const &it) const
      {
        return compare(it) >= 0;
      }
      size_t operator - (const_iterator const &it) const
      {
        if (!ptr || !it.ptr) return 0;
        return ptr - it.ptr;
      }
    };
    size_t size() const
    {
      return count;
    }
    void resize(size_t n)
    {
      while (size() < n) push_back(T());
      while (size() > n) pop_back();
    }
    bool empty() const
    {
      return size() == 0;
    }
    void reserve(size_t n)
    {
      if (capacity < n) {
        T *newarr = (T *)new char [sizeof(T) * n];
        for (size_t i = 0; i < count; i++) {
          new(newarr + i) T(array[i]);
          array[i].~T();
        }
        delete[] array;
        array = newarr;
        capacity = n;
      }
    }
    void clear()
    {
      for (size_t i = 0; i < count; i++) {
        array[i].~T();
      }
      count = 0;
    }
    iterator begin()
    {
      if (array) {
        return iterator(array, array + count);
      } else {
        return iterator(0, 0);
      }
    }
    const_iterator begin() const
    {
      if (array) {
        return const_iterator(array, array + count);
      } else {
        return const_iterator(0, 0);
      }
    }
    iterator end()
    {
      if (array) {
        return iterator(array + count, array + count);
      } else {
        return iterator(0, 0);
      }
    }
    const_iterator end() const
    {
      if (array) {
        return const_iterator(array + count, array + count);
      } else {
        return const_iterator(0, 0);
      }
    }
    iterator insert(iterator it, const_iterator b, const_iterator e)
    {
      if (b < e) {
        size_t i;
        if (it == end()) {
          i = count;
        } else {
          i = it.ptr - array;
        }
        size_t next = 0;
        size_t n = e - b;
        if (n > capacity - count) {
          vector newvec;
          newvec.capacity = ((count + n + 7) & ~7) * 2;
          newvec.array = (T *)new char [sizeof(T) * newvec.capacity];
          if (array && i > 0) {
            newvec.insert(newvec.end(), begin(), begin() + i);
          }
          newvec.insert(newvec.end(), b, e);
          next = newvec.size();
          if (array && count - i > 0) {
            newvec.insert(newvec.end(), begin() + i, end());
          }
          clear();
          delete array;
          capacity = newvec.capacity;
          array = newvec.array;
          count = newvec.count;
          newvec.capacity = 0;
          newvec.count = 0;
          newvec.array = 0;
        } else {
          size_t mv = count - i;
          for (size_t j = 0; j < mv; j++) {
            new(array + count + n - j - 1) T(array[count - j - 1]);
            array[count - j - 1].~T();
          }
          for (size_t j = 0; j < n; j++) {
            new(array + i + j) T(b.ptr[j]);
          }
          count += n;
          next = i + n;
        }
        return iterator(array + next, array + count);
      }
      return iterator(0, 0);
    }
    iterator insert(iterator it, T const v)
    {
      T const *p = &v;
      return insert(it, p, p + 1);
    }
    void push_back(T const &t)
    {
      T const *p = &t;
      insert(end(), p, p + 1);
    }
    void pop_back()
    {
      if (count > 0) {
        count--;
        array[count].~T();
      }
    }
    T &operator [] (size_t i)
    {
      return array[i];
    }
    T const &operator [] (size_t i) const
    {
      return array[i];
    }
  };

  template <typename T> class list {
  private:
    struct node_t {
      node_t *next;
      node_t *prev;
      T val;
      node_t(T const &v)
        : val(v)
        , next(0)
        , prev(0)
      {
      }
    };
    node_t *first;
    node_t *last;
    size_t count;
  public:
    list()
      : count(0)
      , first(0)
      , last(0)
    {
    }
    list(list const &r)
      : count(0)
      , first(0)
      , last(0)
    {
      for (const_iterator it = r.begin(); it != r.end(); it++) {
        push_back(*it);
      }
    }
    ~list()
    {
      clear();
    }
    void operator = (list const &r)
    {
      clear();
      for (const_iterator it = r.begin(); it != r.end(); it++) {
        push_back(*it);
      }
    }
    size_t size() const
    {
      return count;
    }
    bool empty() const
    {
      return size() == 0;
    }
    void clear()
    {
      while (first) {
        erase(begin());
      }
    }
    class const_iterator;
    class iterator {
      friend class list;
      friend class const_iterator;
    private:
      node_t *node;
    public:
      iterator(node_t *node)
        : node(node)
      {
      }
      bool operator == (iterator const &it) const
      {
        return node == it.node;
      }
      bool operator != (iterator const &it) const
      {
        return !operator == (it);
      }
      void operator ++ ()
      {
        if (node) node = node->next;
      }
      void operator ++ (int)
      {
        if (node) node = node->next;
      }
      void operator -- ()
      {
        if (node) node = node->prev;
      }
      void operator -- (int)
      {
        if (node) node = node->prev;
      }
      iterator operator + (size_t n) const
      {
        iterator it(node);
        while (it.node && n > 0) it++;
        return it;
      }
      iterator operator - (size_t n) const
      {
        iterator it(node);
        while (it.node && n > 0) it--;
        return it;
      }
      T &operator * ()
      {
        return node->val;
      }
      T *operator -> ()
      {
        return &node->val;
      }
    };
    class const_iterator {
    private:
      friend class list;
      node_t const *node;
    public:
      const_iterator(node_t const *node)
        : node(node)
      {
      }
      const_iterator(iterator const &it)
        : node(it.node)
      {
      }
      bool operator == (const_iterator const &it) const
      {
        return node == it.node;
      }
      bool operator != (const_iterator const &it) const
      {
        return !operator == (it);
      }
      void operator ++ ()
      {
        if (node) node = node->next;
      }
      void operator ++ (int)
      {
        if (node) node = node->next;
      }
      void operator -- ()
      {
        if (node) node = node->prev;
      }
      void operator -- (int)
      {
        if (node) node = node->prev;
      }
      const_iterator operator + (size_t n) const
      {
        const_iterator it(node);
        while (it.node && n > 0) it++;
        return it;
      }
      const_iterator operator - (size_t n) const
      {
        const_iterator it(node);
        while (it.node && n > 0) it--;
        return it;
      }
      T const &operator * () const
      {
        return node->val;
      }
      T const *operator -> () const
      {
        return &node->val;
      }
    };
    iterator begin()
    {
      return iterator(first);
    }
    const_iterator begin() const
    {
      return const_iterator(first);
    }
    iterator end()
    {
      return iterator(0);
    }
    const_iterator end() const
    {
      return const_iterator(0);
    }
    void erase(iterator it)
    {
      if (first) {
        if (it.node == first) {
          first = it.node->next;
          if (first && first->next) first->next->prev = 0;
        } else if (it.node == last) {
          last = it.node->prev;
          if (last && last->prev) last->prev->next = 0;
        } else {
          if (it.node->prev) it.node->prev->next =it.node->next;
          if (it.node->next) it.node->next->prev =it.node->prev;
        }
        if (!first || !last) {
          first = last = 0;
        }
        delete it.node;
      }
    }
    iterator insert(iterator it, T const &v)
    {
      if (first) {
        node_t *node = new node_t(v);
        if (it.node) {
          if (it.node == first) {
            node->next = first;
            if (first) first->prev = node;
            first = node;
          } else if (it.node == last) {
            node->prev = last;
            if (last) last->next = node;
            last = node;
          } else {
            node->next = it.node;
            node->prev = it.node->prev;
            if (node->prev) node->prev->next = node;
            if (node->next) node->next->prev = node;
          }
        } else {
          node_t *prev = last;
          if (prev) prev->next = node;
          node->prev = prev;
          last = node;
        }
        return iterator(node);
      } else {
        first = last = new node_t(v);
        return iterator(first);
      }
    }
    void push_back(T const &v)
    {
      insert(end(), v);
    }
  };

  template <typename T> T const *zerostring();
  template <> inline char const *zerostring<char>() { return ""; }

  template <typename T> class t_stringbuffer {
  private:
    struct fragment_t {
      fragment_t *next;
      size_t size;
      size_t used;
      T data[1];
    };
    struct core_t {
      unsigned int ref;
      mutable fragment_t *fragment;
      core_t()
        : ref(0)
        , fragment(0)
      {
      }
    };
    struct data_ {
      core_t *core;
      data_()
        : core(0)
      {
      }
    } data;
    void assign(core_t *p)
    {
      if (p) {
        p->ref++;
      }
      if (data.core) {
        if (data.core->ref > 1) {
          data.core->ref--;
        } else {
          internal_clear();
          delete data.core;
        }
      }
      data.core = p;
    }
    static void store(T const *ptr, T const *end, T *dst)
    {
      while (ptr < end) {
        new (dst) T(*ptr);
        ptr++;
        dst++;
      }
    }
    void internal_clear() const
    {
      while (data.core->fragment) {
        fragment_t *next = data.core->fragment->next;
        T *ptr = data.core->fragment->data;
        T *end = data.core->fragment->data + data.core->fragment->used;
        while (ptr < end) {
          ptr->~T();
          ptr++;
        }
        delete[] (unsigned char *)data.core->fragment;
        data.core->fragment = next;
      }
    }
    T *internal_get() const
    {
      if (!data.core->fragment) {
        return 0;
      }
      if (data.core->fragment->next) {
        size_t len = size();
        fragment_t *newptr = (fragment_t *)new unsigned char [sizeof(fragment_t) + sizeof(T) * len];
        newptr->next = 0;
        newptr->size = len;
        newptr->used = len;
        memset(&newptr->data[len], 0, sizeof(T));
        fragment_t *f = data.core->fragment;
        while (f && len > 0) {
          len -= f->used;
          store(f->data, f->data + f->used, newptr->data + len);
          f = f->next;
        }
        internal_clear();
        data.core->fragment = newptr;
      }
      return data.core->fragment->data;
    }
    void modify()
    {
      if (data.core->ref == 1) {
        return;
      }
      t_stringbuffer str(c_str(), size());
      assign(str.data.core);
    }
  public:
    t_stringbuffer()
    {
      assign(new core_t());
    }
    t_stringbuffer(T const *ptr)
    {
      assign(new core_t());
      print(ptr);
    }
    t_stringbuffer(T const *ptr, size_t len)
    {
      assign(new core_t());
      print(ptr, len);
    }
    t_stringbuffer(T const *begin, T const *end)
    {
      assign(new core_t());
      print(begin, end);
    }
    t_stringbuffer(t_stringbuffer const &r)
    {
      assign(r.data.core);
    }
    t_stringbuffer(vector<T> const &vec)
    {
      assign(new core_t());
      if (!vec.empty()) {
        print(&vec[0], vec.size());
      }
    }
    ~t_stringbuffer()
    {
      assign(0);
    }
    void operator = (t_stringbuffer const &r)
    {
      assign(r.data.core);
    }
    void clear()
    {
      modify();
      internal_clear();
    }
    void print(T const *ptr, size_t len)
    {
      modify();
      if (ptr) {
        if (len > 0) {
          if (data.core->fragment && data.core->fragment->size > data.core->fragment->used) {
            size_t n = data.core->fragment->size - data.core->fragment->used;
            if (n > len) {
              n = len;
            }
            store(ptr, ptr + n, data.core->fragment->data + data.core->fragment->used);
            data.core->fragment->used += n;
            data.core->fragment->data[data.core->fragment->used] = 0;
            ptr += n;
            len -= n;
          }
          if (len > 0) {
            size_t n = 4096;
            if (n < len) {
              n = len;
            }
            fragment_t *newptr = (fragment_t *)new unsigned char [sizeof(fragment_t) + sizeof(T) * n];
            newptr->next = data.core->fragment;
            newptr->size = n;
            newptr->used = len;
            store(ptr, ptr + len, newptr->data);
            newptr->data[newptr->used] = 0;
            data.core->fragment = newptr;
          }
        }
      }
    }
    void print(T const *begin, T const *end)
    {
      print(begin, end - begin);
    }
    void print(T const *ptr)
    {
      print(ptr, std::char_traits<T>::length(ptr));
    }
    void print(T const &t)
    {
      print(&t, 1);
    }
    void print(t_stringbuffer const &r)
    {
      print(r.c_str(), r.size());
    }
    size_t size() const
    {
      size_t len = 0;
      fragment_t *f = data.core->fragment;
      while (f) {
        len += f->used;
        f = f->next;
      }
      return len;
    }
    bool empty() const
    {
      return size() == 0;
    }
    T const *c_str() const
    {
      T *p = internal_get();
      return p ? p : zerostring<T>();
    }
    int compare(t_stringbuffer const &r) const
    {
      if (data.core == r.data.core) return true;
      if (empty() && r.empty()) return true;
      return t_strcmp(c_str(), r.c_str());
    }
    T operator [] (size_t i) const
    {
      return c_str()[i];
    }
    bool operator == (t_stringbuffer const &r) const
    {
      return compare(r) == 0;
    }
    bool operator != (t_stringbuffer const &r) const
    {
      return compare(r) != 0;
    }
    bool operator < (t_stringbuffer const &r) const
    {
      return compare(r) < 0;
    }
    bool operator > (t_stringbuffer const &r) const
    {
      return compare(r) > 0;
    }
    bool operator <= (t_stringbuffer const &r) const
    {
      return compare(r) <= 0;
    }
    bool operator >= (t_stringbuffer const &r) const
    {
      return compare(r) >= 0;
    }

    t_stringbuffer operator += (t_stringbuffer const &s)
    {
      print(s);
      return *this;
    }
    t_stringbuffer operator += (T const *s)
    {
      print(s);
      return *this;
    }
    t_stringbuffer operator += (T s)
    {
      print(s);
      return *this;
    }
  };

  // operator +

  template <typename T> inline t_stringbuffer<T> operator + (t_stringbuffer<T> const &left, t_stringbuffer<T> const &right)
  {
    t_stringbuffer<T> t = left;
    t.print(right);
    return t;
  }

  template <typename T> inline t_stringbuffer<T> operator + (t_stringbuffer<T> const &left, char const *right)
  {
    return left + t_stringbuffer<T>(right);
  }

  template <typename T> inline t_stringbuffer<T> operator + (char const *left, t_stringbuffer<T> const &right)
  {
    return t_stringbuffer<T>(left) + right;
  }

  template <typename T> inline t_stringbuffer<T> operator + (t_stringbuffer<T> const &left, char right)
  {
    return left + t_stringbuffer<T>(right);
  }

  template <typename T> inline t_stringbuffer<T> operator + (char left, t_stringbuffer<T> const &right)
  {
    return t_stringbuffer<T>(left) + right;
  }

  typedef t_stringbuffer<char> string;

} // namespace tiny


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
  tiny::string name;
};

struct question_t {
  tiny::string name;
  uint16_t type;
  uint16_t clas;
};

struct answer_t {
  tiny::string name;
  uint16_t type;
  uint16_t clas;
  uint32_t ttl;
  tiny::vector<char> data;
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

int decode_name(char const *begin, char const *end, char const *ptr, tiny::vector<char> *out)
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

int decode_name(char const *begin, char const *end, char const *ptr, tiny::string *name)
{
  tiny::vector<char> tmp;
  tmp.reserve(100);
  int n = decode_name(begin, end, ptr, &tmp);
  if (n > 0 && !tmp.empty()) {
    char const *p = &tmp[0];
    *name = tiny::string(p, p + tmp.size());
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

void parse_response(char const *begin, char const *end, dns_header_t *header, tiny::list<question_t> *questions, tiny::list<answer_t> *answers)
{
  char const *ptr = begin;

  header->id = read_uint16_be(&ptr[0]);
  header->flags = read_uint16_be(&ptr[2]);
  header->qdcount = read_uint16_be(&ptr[4]);
  header->ancount = read_uint16_be(&ptr[6]);
  header->nscount = read_uint16_be(&ptr[8]);
  header->arcount = read_uint16_be(&ptr[10]);
  ptr += 12;

  tiny::vector<char> res;

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
        tiny::list<answer_t>::iterator it = answers->insert(answers->end(), answer_t());
        *it = a;
        it->data.resize(rdlen);
        memcpy(&it->data[0], ptr, rdlen);
        ptr += rdlen;
      }
    }
  }
}

tiny::string decode_netbios_name(tiny::string const &name, int *restype)
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
    return tiny::string((char const *)tmp, i);
  }
  *restype = -1;
  return tiny::string();
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

void write(tiny::vector<char> *out, char c)
{
  out->push_back(c);
}

void write(tiny::vector<char> *out, char const *src, int len)
{
  if (src && len > 0) {
    out->insert(out->end(), src, src + len);
  }
}

void write_us(tiny::vector<char> *out, uint16_t v)
{
  v = htons(v);
  write(out, (char const *)&v, 2);
}

void write_ul(tiny::vector<char> *out, uint32_t v)
{
  v = htonl(v);
  write(out, (char const *)&v, 4);
}

void write_name(tiny::vector<char> *out, tiny::string const &name)
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


static void write_dns_header(tiny::vector<char> *out, uint16_t id, uint16_t flags, uint16_t qdcount, uint16_t ancount, uint16_t nscount, uint16_t arcount)
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

void write_dns_question_rr(tiny::vector<char> *out, tiny::string const &name, uint16_t type, uint16_t clas)
{
  write_name(out, name);
  write_us(out, type);
  write_us(out, clas);
}

void write_dns_answer_rr(tiny::vector<char> *out, tiny::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, dns_a_record_t const &item)
{
  uint32_t addr = htonl(item.addr);
  write_name(out, name);
  write_us(out, type);
  write_us(out, clas);
  write_ul(out, ttl);
  write_us(out, 4);
  write(out, (char const *)&addr, 4);
}

void write_wins_rr(tiny::vector<char> *out, tiny::string const &name, uint16_t type, uint16_t clas, uint32_t ttl, uint16_t nameflags, dns_a_record_t const &item)
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

void make_wins_response(dns_header_t const &header, question_t const &q, dns_a_record_t const &r, tiny::vector<char> *out)
{
  if (q.type == DNS_TYPE_NB) {
    uint16_t nameflags = 0;
    write_dns_header(out, header.id, 0x8580, 0, 1, 0, 0);
    write_wins_rr(out, q.name, q.type, q.clas, TTL, nameflags, r);
  }
}

bool is_my_name(tiny::string const &name)
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
MDNSResponder mdns;

void process_wins()
{
  WiFiUDP *udp = &udp137;
  char buf[2000];
  int len = udp->parsePacket();
  if (len > 0 && len <= sizeof(buf)) {
    udp->read(buf, len); // read the packet into the buffer
    tiny::vector<char> res;
    dns_header_t header;
    tiny::list<question_t> questions;
    tiny::list<answer_t> answers;
    parse_response(buf, buf + len, &header, &questions, &answers);
    if ((header.flags & 0xf800) == 0x0000) { // standard query
      for (tiny::list<question_t>::const_iterator it = questions.begin(); it != questions.end(); it++) {
        question_t const &q = *it;
        if (q.clas == DNS_CLASS_IN) {
          if (q.type == DNS_TYPE_PTR) {
            // ignore
          } else {
            tiny::string name;
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
  mdns.begin(HOSTNAME, WiFi.localIP());
}

void loop()
{
  process_wins();
}

