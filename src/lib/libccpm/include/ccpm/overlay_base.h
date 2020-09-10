#ifndef __CCPM_OVERLAY_BASE_H__
#define __CCPM_OVERLAY_BASE_H__

#include <common/cycles.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"


#define __NARG__(...)  __NARG_I_(__VA_ARGS__,__RSEQ_N())
#define __NARG_I_(...) __ARG_N(__VA_ARGS__)
#define __ARG_N( \
      _1, _2, _3, _4, _5, _6, _7, _8, _9,_10, \
     _11,_12,_13,_14,_15,_16,_17,_18,_19,_20, \
     _21,_22,_23,_24,_25,_26,_27,_28,_29,_30, \
     _31,_32,_33,_34,_35,_36,_37,_38,_39,_40, \
     _41,_42,_43,_44,_45,_46,_47,_48,_49,_50, \
     _51,_52,_53,_54,_55,_56,_57,_58,_59,_60, \
     _61,_62,_63,N,...) N
#define __RSEQ_N() \
     63,62,61,60,                   \
     59,58,57,56,55,54,53,52,51,50, \
     49,48,47,46,45,44,43,42,41,40, \
     39,38,37,36,35,34,33,32,31,30, \
     29,28,27,26,25,24,23,22,21,20, \
     19,18,17,16,15,14,13,12,11,10, \
     9,8,7,6,5,4,3,2,1,0

#define _VFUNC_(name, n) name##n
#define _VFUNC(name, n) _VFUNC_(name, n)
#define VFUNC(func, ...) _VFUNC(func, __NARG__(__VA_ARGS__)) (__VA_ARGS__)

#define DECLARE_OVERLAY_CHAIN2(TYPE, C1) using TYPE = Opaque_value<C1<End>>;
#define DECLARE_OVERLAY_CHAIN3(TYPE, C1, C2) using TYPE = Opaque_value<C1<C2<End>>>;
#define DECLARE_OVERLAY_CHAIN4(TYPE, C1, C2, C3) using TYPE = Opaque_value<C1<C2<C3<End>>>>;
#define DECLARE_OVERLAY_CHAIN5(TYPE, C1, C2, C3, C4) using TYPE = Opaque_value<C1<C2<C3<C4<End>>>>>;
#define DECLARE_OVERLAY_CHAIN6(TYPE, C1, C2, C3, C4, C5) using TYPE = Opaque_value<C1<C2<C3<C4<C5<End>>>>>>;
#define DECLARE_OVERLAY_CHAIN7(TYPE, C1, C2, C3, C4, C5, C6) using TYPE = Opaque_value<C1<C2<C3<C4<C5<C6<End>>>>>>>;

#define DECLARE_OVERLAY_CHAIN(...) VFUNC(DECLARE_OVERLAY_CHAIN, __VA_ARGS__)


namespace ccpm
{

class End
{
};
 
template <class Base=End>
class Opaque_value : public Base
{
public:
  void * opaque_value() {
    return static_cast<void*>(this);
  }
} __attribute__((packed));

template <class Base=End>
class Timestamps : public Base
{
public:
  Timestamps() {}

  void update_last_modified() {
    _last_modified = rdtsc();
    pmem_persist(_last_modified,sizeof(_last_modified));
  }

private: 
  cpu_time_t _last_modified; 
} __attribute__((packed));

template <class Base=End>
class Version : public Base
{
public:
  Version() : _major(1), _minor(0) {
  }

  void increment_minor() {
    _minor++;
    pmem_persist(_minor, sizeof(_minor));
  }
  
private:
  uint32_t _major;
  uint32_t _minor;
} __attribute__((aligned));

}

#pragma GCC diagnostic pop

#endif // __CCPM_OVERLAY_BASE_H__