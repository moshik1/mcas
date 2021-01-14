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

#ifndef _MCAS_SHARD_AC_STORE_H_
#define _MCAS_SHARD_AC_STORE_H_

#include <api/kvstore_itf.h>
#include <common/logging.h>
#include <common/string_view.h>
#include <array>
#include <map>
#include <string>

namespace mcas
{
  /* shim for access control, added above an IKVStore component */
  struct ac_store
    : public component::IKVStore
    , private common::log_source
  {
  private:
    using string_view = common::string_view;
    struct access
    {
      using access_type = unsigned;
      static constexpr access_type read = 0x4;
      static constexpr access_type write = 0x2;
      static constexpr access_type list = 0x1;
      static constexpr access_type none = 0x0;
      static const std::string prefix;
    };

    component::Itf_ref<component::IKVStore> _store;
    std::multimap<pool_t, std::array<unsigned,2>> _access_allowed;
    bool access_ok(const char *func, pool_t pool, access::access_type access_required) const;
    bool access_ok(const char *func, pool_t pool, const string_view key, access::access_type access_required) const;
    static bool is_data(string_view key);

  public:
    ac_store(unsigned debug_level, component::IKVStore *store);
    int thread_safety() const override;
    int get_capability(Capability cap) const override;
    pool_t create_auth_pool(const std::string& name,
                             uint64_t      auth_id,
                             const size_t       size,
                             flags_t            flags,
                             uint64_t           expected_obj_count,
                             const Addr         base_addr_unused) override;
    pool_t open_auth_pool(const std::string& name,
                           uint64_t      auth_id,
                           flags_t flags,
                           const Addr base_addr_unused) override;
    status_t close_pool(pool_t pool) override;
    status_t delete_pool(const std::string& name) override;
    status_t get_pool_regions(pool_t pool, nupm::region_descriptor & out_regions) override;
    status_t grow_pool(const pool_t pool,
                             size_t increment_size,
                             size_t& reconfigured_size) override;
    status_t put(const pool_t       pool,
                       const std::string& key,
                       const void*        value,
                       size_t       value_len,
                       flags_t            flags) override;
    status_t put_direct(const pool_t       pool,
                              const std::string& key,
                              const void*        value,
                              const size_t       value_len,
                              memory_handle_t    handle,
                              flags_t            flags) override;
    status_t resize_value(const pool_t       pool,
                                const std::string& key,
                                const size_t       new_size,
                                const size_t       alignment) override;
    status_t get(const pool_t       pool,
                       const std::string& key,
                       void*&             out_value, /* release with free_memory() API */
                       size_t&            out_value_len) override;
    status_t get_direct(pool_t             pool,
                              const std::string& key,
                              void*              out_value,
                              size_t&            out_value_len,
                              memory_handle_t    handle) override;
    status_t get_attribute(pool_t                 pool,
                                 Attribute              attr,
                                 std::vector<uint64_t>& out_value,
                                 const std::string*     key) override;
    status_t swap_keys(const pool_t pool,
                             const std::string key0,
                             const std::string key1) override;
    status_t set_attribute(const pool_t                 pool,
                                 const Attribute              attr,
                                 const std::vector<uint64_t>& value,
                                 const std::string*           key) override;
    status_t allocate_direct_memory(void*& vaddr,
                                          size_t len,
                                          memory_handle_t& handle) override;
    status_t free_direct_memory(memory_handle_t handle) override;
    memory_handle_t register_direct_memory(void* vaddr,
                                                 size_t len) override;
    status_t unregister_direct_memory(memory_handle_t handle) override;
    status_t lock(const pool_t       pool,
                        const std::string& key,
                        const lock_type_t  type,
                        void*&             out_value,
                        size_t&            inout_value_len,
                        key_t&             out_key_handle,
                        const char**       out_key_ptr) override;
    status_t unlock(const pool_t pool,
                          const key_t key_handle,
                          const unlock_flags_t flags) override;
    status_t atomic_update(const pool_t                   pool,
                                 const std::string&             key,
                                 const std::vector<Operation*>& op_vector,
                                 bool                           take_lock) override;
    status_t erase(pool_t pool, const std::string& key) override;
    size_t count(pool_t pool) override;
    status_t map(const pool_t pool,
                       std::function<int(const void* key,
                                         const size_t key_len,
                                         const void* value,
                                         const size_t value_len)> function) override;
    status_t map(const pool_t pool,
                       std::function<int(const void*              key,
                                         const size_t             key_len,
                                         const void*              value,
                                         const size_t             value_len,
                                         const common::tsc_time_t timestamp)> function,
                       const common::epoch_time_t t_begin,
                       const common::epoch_time_t t_end) override;
    status_t map_keys(const pool_t pool, std::function<int(const std::string& key)> function) override;
    pool_iterator_t open_pool_iterator(const pool_t pool) override;
    status_t deref_pool_iterator(const pool_t       pool,
                                       pool_iterator_t    iter,
                                       const common::epoch_time_t t_begin,
                                       const common::epoch_time_t t_end,
                                       pool_reference_t&  ref,
                                       bool&              time_match,
                                       bool               increment) override;
    status_t close_pool_iterator(const pool_t pool,
                                       pool_iterator_t iter) override;
    status_t free_memory(void* p) override;
    status_t allocate_pool_memory(const pool_t pool,
                                        const size_t size,
                                        const size_t alignment_hint,
                                        void*&       out_addr) override;
    status_t free_pool_memory(pool_t pool, const void* addr, size_t size) override;
    status_t flush_pool_memory(pool_t pool, const void* addr, size_t size) override;
    status_t ioctl(const std::string& command) override;
    void debug(pool_t pool, unsigned cmd, uint64_t arg) override;
    void* query_interface(component::uuid_t&u) { return _store->query_interface(u); }
  };
}

#endif
