#include "ruby.h"
#include "st.h"

VALUE
hash_succ(hash, key)
    VALUE hash, key;
{
  VALUE ary, val, one;
  st_table *tbl;
  int length, count, ofs;
  
  one = INT2FIX(1);
  tbl = RHASH(hash)->tbl;
  
  switch(TYPE(key)) {
  case T_STRING:
    if (st_lookup(tbl, key, &val)) {
      count = FIX2INT(val);
      count++;
      st_insert(tbl, key, INT2FIX(count));
    } else {
      st_add_direct(tbl, rb_str_new4(key), one);
    }
    break;
  case T_ARRAY:
    ary = key;
    length = RARRAY(ary)->len;
    for(ofs=0; ofs < length; ofs++) {
      key = RARRAY(ary)->ptr[ofs];
      if (st_lookup(tbl, key, &val)) {
        count = FIX2INT(val);
        count++;
        st_insert(tbl, key, INT2FIX(count));
      } else {
        st_add_direct(tbl, rb_str_new4(key), one);
      }
    }
    break;
  }
  return hash;
}

void
Init_hashsucc()
{
  rb_define_method(rb_cHash,"succ!", hash_succ, 1);
}
