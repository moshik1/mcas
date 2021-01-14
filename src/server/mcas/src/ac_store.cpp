/*
  Copyright [2021] [IBM Corporation]
  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at
  http://www.apache.org/licenses/LICENSE-2.0
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

#include "ac_store.h"

const std::string mcas::ac_store::access::prefix = "acs."; /* different from hstore's equivalent, ".ac", for now */

mcas::ac_store::ac_store(unsigned debug_level_, component::IKVStore *store_)
      : common::log_source(debug_level_ + 2)
      , _store(store_)
      , _access_allowed{}
{}

bool mcas::ac_store::is_data(const string_view key_)
{
  return key_.find(access::prefix.data(), 0, access::prefix.size()) != 0;
}

bool mcas::ac_store::access_ok(const char *func_, pool_t pool_, access::access_type access_required_) const
{
  auto p = _access_allowed.find(pool_);
  bool ok = p != _access_allowed.end()
    && ( ( p->second[0] & p->second[1] & access_required_ ) == access_required_ );
  if ( ! ok )
  {
    CPLOG(1, "%s: ACCESS fail for %s need %u have (%s) have %u & %u", __func__
      , func_
      , access_required_
      , p != _access_allowed.end() ? "found" : "at_end"
      , p != _access_allowed.end() ? p->second[0] : 0
      , p != _access_allowed.end() ? p->second[1] : 0
    );
  }
  return ok;
}

bool mcas::ac_store::access_ok(const char *func_, pool_t pool_, const string_view key_, access::access_type access_required_) const
{
  auto p = _access_allowed.find(pool_);

     std::size_t ix =
          key_.find(access::prefix.data(), 0, access::prefix.size()) == 0
          ? 0
          : 1
          ;

  bool ok = p != _access_allowed.end()
        && ( ( p->second[ix] & access_required_ ) == access_required_ );

  if ( ! ok )
  {
    CPLOG(1, "%s: ACCESS fail for %s key %.*s need %u have (%s) type %zu %u", __func__
      , func_
      , int(key_.size()), key_.begin()
      , access_required_
      , p != _access_allowed.end() ? "found" : "at_end"
      , ix
      , p != _access_allowed.end() ? p->second[ix] : 0
    );
  }
  return ok;
}

int mcas::ac_store::thread_safety() const { return _store->thread_safety(); }

int mcas::ac_store::get_capability(Capability cap) const { return _store->get_capability(cap); }

auto mcas::ac_store::create_auth_pool(const std::string& name,
                             uint64_t           auth_id,
                             const size_t       size,
                             flags_t            flags,
                             uint64_t           expected_obj_count,
                             const Addr         base_addr_unused) -> pool_t
{
      auto pool = _store->create_pool(name, size, flags, expected_obj_count, base_addr_unused);
  if ( auth_id != 0 )
  {
      std::string auth_str = std::to_string(auth_id);
      /* should write 0-length data, but that fails with E_BAD_PARAM */
      auto rc = _store->put(pool, access::prefix + "auth_check.", "x", 1);
      auto rc0 = _store->put(pool, access::prefix + "control." + auth_str, "7", 1);
      auto rc1 = _store->put(pool, access::prefix + "data." + auth_str, "7", 1);
      _access_allowed.insert({pool, std::array<access::access_type, 2>{7, 7}});
      CPLOG(1, "%s: rc %d %d %d ACCESSes %u %u", __func__, rc, rc0, rc1, 7, 7);
  }
      return pool;
}

auto mcas::ac_store::open_auth_pool(const std::string& name,
                             uint64_t           auth_id,
                           flags_t flags = 0,
                           const Addr base_addr_unused = Addr{0}) -> pool_t
{
  auto pool = _store->open_auth_pool(name, auth_id, flags, base_addr_unused);
  std::size_t size = 1;
  std::array<char,1> buffer;
  auto rc = _store->get_direct(pool, access::prefix + "auth_check.", &buffer[0], size);
  if ( rc == 0 && size == 1 )
  {
    std::string auth_str = std::to_string(auth_id);
    std::array<access::access_type, 2> ac{access::none, access::none};
    std::size_t size0 = 1;
    auto rc0 = _store->get_direct(pool, access::prefix + "control." + auth_str, &buffer[0], size0);
    if ( rc0 == S_OK && size0 == 1 ) ac[0] = buffer[0] - '0';
    std::size_t size1 = 1;
    auto rc1 = _store->get_direct(pool, access::prefix + "data." + auth_str, &buffer[0], size1);
    if ( rc1 == S_OK && size1 == 1 ) ac[1] = buffer[0] - '0';
    _access_allowed.insert({pool, ac});
    CPLOG(1, "%s: rc %d %d sizes %zu %zu ACCESSes {%u %u}", __func__, rc0, rc1, size0, size1, ac[0], ac[1]);
  }
  else
  {
      std::array<access::access_type, 2> ac{access::read|access::write||access::list, access::read|access::write||access::list};
      _access_allowed.insert({pool, ac});
  }
  return pool;
}

auto mcas::ac_store::close_pool(pool_t pool) -> status_t
{
  auto it = _access_allowed.find(pool);
  if ( it != _access_allowed.end() )
  {
      _access_allowed.erase(it);
  }
  return _store->close_pool(pool);
}

auto mcas::ac_store::delete_pool(const std::string& name) -> status_t
{
      return _store->delete_pool(name);
}

auto mcas::ac_store::get_pool_regions(pool_t pool, nupm::region_descriptor & out_regions) -> status_t
{
      return _store->get_pool_regions(pool, out_regions);
}

auto mcas::ac_store::grow_pool(const pool_t pool,
                             size_t increment_size,
                             size_t& reconfigured_size) -> status_t
{
      return _store->grow_pool(pool, increment_size, reconfigured_size);
}

auto mcas::ac_store::put(const pool_t       pool,
                       const std::string& key,
                       const void*        value,
                       size_t       value_len,
                       flags_t            flags) -> status_t
{
      if ( ! access_ok(__func__, pool, key, access::write) ) return E_FAIL;
      return _store->put(pool, key, value, value_len, flags);
}

auto mcas::ac_store::put_direct(const pool_t       pool,
                              const std::string& key,
                              const void*        value,
                              const size_t       value_len,
                              memory_handle_t    handle,
                              flags_t            flags) -> status_t
{
      if ( ! access_ok(__func__, pool, key, access::write) ) return E_FAIL;
      return _store->put_direct(pool, key, value, value_len, handle, flags);
}

auto mcas::ac_store::resize_value(const pool_t       pool,
                                const std::string& key,
                                const size_t       new_size,
                                const size_t       alignment) -> status_t
{
    if ( ! access_ok(__func__, pool, key, access::write) ) return E_FAIL;
    return _store->resize_value(pool, key, new_size, alignment);
}

auto mcas::ac_store::get(const pool_t       pool,
                       const std::string& key,
                       void*&             out_value, /* release with free_memory() API */
                       size_t&            out_value_len) -> status_t
{
    if ( ! access_ok(__func__, pool, key, access::read) ) return E_FAIL;
    return _store->get(pool, key, out_value, out_value_len);
}

auto mcas::ac_store::get_direct(pool_t             pool,
                              const std::string& key,
                              void*              out_value,
                              size_t&            out_value_len,
                              memory_handle_t    handle = HANDLE_NONE) -> status_t
{
      if ( ! access_ok(__func__, pool, key, access::read) ) return E_FAIL;
      return _store->get_direct(pool, key, out_value, out_value_len, handle);
}

auto mcas::ac_store::get_attribute(pool_t                 pool,
                                 Attribute              attr,
                                 std::vector<uint64_t>& out_value,
                                 const std::string*     key = nullptr) -> status_t
{
      return _store->get_attribute(pool, attr, out_value, key);
}

auto mcas::ac_store::swap_keys(const pool_t pool,
                             const std::string key0,
                             const std::string key1) -> status_t
{
      if ( ! access_ok(__func__, pool, key0, access::write) ) return E_FAIL;
      if ( ! access_ok(__func__, pool, key1, access::write) ) return E_FAIL;
      return _store->swap_keys(pool, key0, key1);
}

auto mcas::ac_store::set_attribute(const pool_t                 pool,
                                 const Attribute              attr,
                                 const std::vector<uint64_t>& value,
                                 const std::string*           key) -> status_t
{
    return _store->set_attribute(pool, attr, value, key);
}

auto mcas::ac_store::allocate_direct_memory(void*& vaddr,
                                          size_t len,
                                          memory_handle_t& handle) -> status_t
{
    return _store->allocate_direct_memory(vaddr, len, handle);
}

auto mcas::ac_store::free_direct_memory(memory_handle_t handle) -> status_t
{
    return _store->free_direct_memory(handle);
}

auto mcas::ac_store::register_direct_memory(void* vaddr,
                                                 size_t len) -> memory_handle_t
{
    return _store->register_direct_memory(vaddr, len);
}

auto mcas::ac_store::unregister_direct_memory(memory_handle_t handle) -> status_t
{
    return _store->unregister_direct_memory(handle);
}

auto mcas::ac_store::lock(const pool_t       pool,
                        const std::string& key,
                        const lock_type_t  type,
                        void*&             out_value,
                        size_t&            inout_value_len,
                        key_t&             out_key_handle,
                        const char**       out_key_ptr) -> status_t
{
    if ( ! access_ok(__func__, pool, key, access::read|access::write) ) return E_FAIL;
    return _store->lock(pool, key, type, out_value, inout_value_len, out_key_handle, out_key_ptr);
}

auto mcas::ac_store::unlock(const pool_t pool,
                          const key_t key_handle,
                          const unlock_flags_t flags) -> status_t
{
    return _store->unlock(pool, key_handle, flags);
}

auto mcas::ac_store::atomic_update(const pool_t                   pool,
                                 const std::string&             key,
                                 const std::vector<Operation*>& op_vector,
                                 bool                           take_lock) -> status_t
{
    if ( ! access_ok(__func__, pool, key, access::read|access::write) ) return E_FAIL;
    return _store->atomic_update(pool, key, op_vector, take_lock);
}

auto mcas::ac_store::erase(pool_t pool, const std::string& key) -> status_t
{
    if ( ! access_ok(__func__, pool, key, access::write) ) return E_FAIL;
  return _store->erase(pool, key);
}

std::size_t mcas::ac_store::count(pool_t pool)
{
    if ( ! access_ok(__func__, pool, access::list) ) return 0;
  std::uint64_t count = 0;
  this->map_keys(pool, [&count,this](const std::string &) -> int { ++count; return 0; });
  return count;
}

auto mcas::ac_store::map(const pool_t pool,
                       std::function<int(const void* key,
                                         const size_t key_len,
                                         const void* value,
                                         const size_t value_len)> function) -> status_t
{
  /* Note: vulnerable to a const_cast */
  if ( ! access_ok(__func__, pool, access::read|access::list) ) return E_FAIL;
    return _store->map(pool, function);
  return
    _store->map(
      pool
      , [&function](const void *key_, size_t key_len_, const void* value_, size_t value_len_) -> int
        {
          return
            is_data(string_view(static_cast<const char *>(key_), key_len_))
            ? function(key_, key_len_, value_, value_len_)
            : 0
            ;
        }
    );
}

auto mcas::ac_store::map(const pool_t pool,
                       std::function<int(const void*              key,
                                         const size_t             key_len,
                                         const void*              value,
                                         const size_t             value_len,
                                         const common::tsc_time_t timestamp)> function,
                       const common::epoch_time_t t_begin,
                       const common::epoch_time_t t_end) -> status_t
{
  /* Note: vulnerable to a const_cast */
  if ( ! access_ok(__func__, pool, access::read|access::list) ) return E_FAIL;
  return
    _store->map(
      pool
      , [&function](const void *key_, size_t key_len_, const void* value_, size_t value_len_, common::tsc_time_t timestamp_) -> int
        {
          return
            is_data(string_view(static_cast<const char *>(key_), key_len_))
            ? function(key_, key_len_, value_, value_len_, timestamp_)
            : 0
            ;
        }
      , t_begin
      , t_end
    );
}

auto mcas::ac_store::map_keys(const pool_t pool, std::function<int(const std::string& key)> function) -> status_t
{
  if ( ! access_ok(__func__, pool, access::read|access::list) ) return E_FAIL;
  return _store->map_keys(
    pool
    , [&function](const std::string & key_) -> int
      {
        return
          is_data(string_view(key_))
          ? function(key_)
          : 0
          ;
      }
  );
}

auto mcas::ac_store::open_pool_iterator(const pool_t pool) -> pool_iterator_t
{
    if ( ! access_ok(__func__, pool, access::read|access::write|access::list) ) return pool_iterator_t();
  /* Note: Needs to return a smarter iterator: one which will admit only "data" keys and not "control" keys */
    return _store->open_pool_iterator(pool);
}

auto mcas::ac_store::deref_pool_iterator(const pool_t       pool,
                                       pool_iterator_t    iter,
                                       const common::epoch_time_t t_begin,
                                       const common::epoch_time_t t_end,
                                       pool_reference_t&  ref,
                                       bool&              time_match,
                                       bool               increment = true) -> status_t
{
    /* Note: vulnerable to a forged iterator */
  auto s = _store->deref_pool_iterator(pool, iter, t_begin, t_end, ref, time_match, increment);
  /* return references only for data keys */
  while ( s == S_OK && ! is_data(ref.get_key()) )
  {
    s = _store->deref_pool_iterator(pool, iter, t_begin, t_end, ref, time_match, increment);
  }
  return s;
}

auto mcas::ac_store::close_pool_iterator(const pool_t pool,
                                       pool_iterator_t iter) -> status_t
{
    return _store->close_pool_iterator(pool, iter);
}

auto mcas::ac_store::free_memory(void* p) -> status_t
{
    return _store->free_memory(p);
}

auto mcas::ac_store::allocate_pool_memory(const pool_t pool,
                                        const size_t size,
                                        const size_t alignment_hint,
                                        void*&       out_addr) -> status_t
{
    return _store->allocate_pool_memory(pool, size, alignment_hint, out_addr);
}

auto mcas::ac_store::free_pool_memory(pool_t pool, const void* addr, size_t size) -> status_t
{
    return _store->free_pool_memory(pool, addr, size);
}

auto mcas::ac_store::flush_pool_memory(pool_t pool, const void* addr, size_t size) -> status_t
{
    return _store->flush_pool_memory(pool, addr, size);
}

auto mcas::ac_store::ioctl(const std::string& command) -> status_t
{
    return _store->ioctl(command);
}

void mcas::ac_store::debug(pool_t pool, unsigned cmd, uint64_t arg)
{
    return _store->debug(pool, cmd, arg);
}
