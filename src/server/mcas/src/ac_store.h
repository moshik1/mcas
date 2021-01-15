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
  namespace access
  {
    using access_type = unsigned;
    constexpr access_type read = 0x4;
    constexpr access_type write = 0x2;
    constexpr access_type list = 0x0; /* Removed. There are no controls on no "list" access */
    constexpr access_type all = read|write|list;
    constexpr access_type none = 0x0;
  }

  /* Shim for access control, added in front of an IKVStore component.
   *
   * Beware: This code "borrows" some of the kvstore data space
   * to store access control values. This may be a source of difficulties
   * when using data space, or adding or modifying data space operations.
   * It might be better to store the control values in a spearate store,
   * as one version of hstore does.
   *
   * Acces control is enabled for pools containing the key _key_prefix+_key_auth_check
   * (which is "acs.auth_check") locating a data item which is at least 8 bytes long.
   * The 8-byte restriction arises, if from nowhere else, mapstore's refusal to accept
   * values shorter than 8 bytes.
   *
   * For pools with access control, keys of the form "acs.control.<auth_id>" andi
   * "acs.data.<auth_id>", where <auth_id> is the decimal string form of an auth_id,
   * specify access rights to control KV pairs (which begin with "acs.") and data
   * KV pairs (which begin with anything else). The access is 7 bytes of zeroesi
   * followed by a digit which specifies the access rights: 4 is read, 2 is write,
   * and 6 is read|write. For example, a pool containing KV pairs
   *   "acs.control.1527" -> "00000004"
   *   "acs.data.1527" -> "00000006"
   * grants auth_di 1527 read access to the KV pairs beginning with "acs." and
   * read/write access to all other KV pairs.
   */
  struct ac_store
    : public component::IKVStore
    , private common::log_source
  {
  private:
    using string_view = common::string_view;
    static constexpr std::size_t ix_control = 0;
    static constexpr std::size_t ix_data = 1;
    static constexpr std::size_t ix_count = 2;

    component::IKVStore *_store;
    std::uint64_t _auth_id;
    /* The same pool may be opened multiple times, so multimap is used to maintain an "open count".
     * When permssion is checked, the permission recorded when some open was called is used.
     */
    std::multimap<pool_t, std::array<unsigned,ix_count>> _access_allowed;
    static const std::string _key_prefix;
    static const std::array<std::string, ix_count> _key_infix; /*  = { "control.", "data." }; */
    /* trouble with mapstore when using values less than 8 bytes long */
    static const std::size_t _value_min_size = 8;
    static const std::string _key_auth_check;
    static const std::string _value_auth_check;

    bool access_ok(const char *func, pool_t pool, access::access_type access_required) const;
    bool access_ok(const char *func, pool_t pool, const string_view key, access::access_type access_required) const;
    static std::string access_key(string_view type, uint64_t auth_id);
    static bool is_data(string_view key);

  public:
    ac_store(unsigned debug_level, component::IKVStore *store, std::uint64_t auth_id);
    ac_store(const ac_store &) = delete;
    ac_store &operator=(const ac_store &) = delete;
    int thread_safety() const override;
    int get_capability(Capability cap) const override;
    pool_t create_pool(const std::string& name,
                             const size_t       size,
                             flags_t            flags,
                             uint64_t           expected_obj_count,
                             const Addr         base_addr_unused) override;
    pool_t open_pool(const std::string& name,
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
