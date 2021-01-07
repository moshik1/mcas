/*
   Copyright [2017-2021] [IBM Corporation]
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

#include "alloc_key.h" /* AK_ACTUAL */
#include "clean_align.h"
#include "definite_lock.h"
#include "lock_impl.h"
#include "pool_iterator.h"
#include "logging.h" /* PREFIX */
#include "monitor_emplace.h"
#include "monitor_pin.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
#include <tbb/scalable_allocator.h> /* scalable_malloc */
#pragma GCC diagnostic pop
#include <algorithm> /* min, max, transform */
#include <cstddef> /* size_t */
#include <cstring> /* memcpy */
#include <limits> /* numeric_limits */
#include <memory> /* make_shared */
#include <new> /* bad_alloc */
#include <stdexcept> /* bad_alloc, domain_error, out_of_range, range_error */
#include <type_traits> /* remove_const */
#include <tuple>
#include <vector>
#include <utility> /* move */

struct dax_manager;

template <typename Handle, typename Allocator, typename Table, typename LockType>
	bool session<Handle, Allocator, Table, LockType>::try_lock(typename std::tuple_element<0, mapped_type>::type &d, lock_type type)
	{
		return
			type == component::IKVStore::STORE_LOCK_READ
			? d.try_lock_shared()
			: d.try_lock_exclusive()
			;
	}

	/* PMEMoid, persist_data_type */
template <typename Handle, typename Allocator, typename Table, typename LockType>
	template <typename OID, typename Persist>
		session<Handle, Allocator, Table, LockType>::session(
			OID
#if USE_CC_HEAP == 2
				heap_oid_
#endif
			, Handle &&pop_
			, Persist *persist_data_
			, unsigned debug_level_
		)
		: Handle(std::move(pop_))
		, common::log_source(debug_level_)
		, _heap(
			Allocator(
#if USE_CC_HEAP == 2
				*new
					(pmemobj_direct(heap_oid_))
					heap_co(heap_oid_)
#elif USE_CC_HEAP == 3 || USE_CC_HEAP == 4
				this->pool() /* not used */
#endif /* USE_CC_HEAP */
			)
		)
		, _pin_seq(undo_redo_pin_data(_heap) || undo_redo_pin_key(_heap))
		, _map(persist_data_, _heap)
		, _atomic_state(*persist_data_, _map)
		, _writes(0)
		, _iterators()
	{}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::writes() const -> std::uint64_t { return _writes; }

template <typename Handle, typename Allocator, typename Table, typename LockType>
	session<Handle, Allocator, Table, LockType>::session(
		AK_ACTUAL
		Handle &&pop_
		, construction_mode mode_
		, unsigned debug_level_
	)
		: Handle(std::move(pop_))
		, common::log_source(debug_level_)
		, _heap(
			Allocator(
				this->pool()->make_heap_access()
			)
		)
		, _pin_seq(undo_redo_pin_data(AK_REF _heap) || undo_redo_pin_key(AK_REF _heap))
		, _map(
			{
#if 0
				AK_REF &this->pool()->persist_data()._persist_map[persist_data::pm_type::ix_meta], mode_, _heap
				,
#endif
				table_type(AK_REF &this->pool()->persist_data()._persist_map[pool_type::persist_data_type::ix_data], mode_, _heap)
			}
		)
		, _atomic_state(this->pool()->persist_data()._persist_atomic, _heap, mode_)
		, _writes(0)
		, _iterators()
	{}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	session<Handle, Allocator, Table, LockType>::~session()
	{
#if USE_CC_HEAP == 3 || USE_CC_HEAP == 4
		this->pool()->quiesce();
#endif
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	bool session<Handle, Allocator, Table, LockType>::undo_redo_pin_data(
		AK_ACTUAL
		allocator_type heap_
	)
	{
#if USE_CC_HEAP == 3
		AK_REF_VOID;
		(void) (heap_);
		return true;
#elif USE_CC_HEAP == 4
		auto &aspd = heap_.pool()->aspd();
		auto armed = aspd.is_armed();
		if ( armed )
		{
			/* _arm_ptr points to a new cptr, within a "large", within a persist_fixed_string */
			auto *pfs = data_type::pfs_from_cptr_ref(*aspd.arm_ptr());

			if ( aspd.was_callback_tested() )
			{
				/* S_uncommitted or S_committed: allocator had an allocation in "in_doubt" state,
				 * meaning that cptr, if not null contains an allocation address and not inline data
				 */
				if ( pfs->get_cptr().P )
				{
					/* S_committed: roll forward */
					pfs->pin(AK_REF aspd.get_cptr(), this->allocator());
				}
				else
				{
					/* S_uncommitted: roll back */
					pfs->set_cptr(aspd.get_cptr(), this->allocator());
				}
			}
			else
			{
				/* S_calling: allocator did not reach "in doubt" state, meaning that
				 * cptr contains null or old inline data.
				 */
				/* roll back */
				pfs->set_cptr(aspd.get_cptr(), this->allocator());
			}
			aspd.disarm(this->allocator());
		}
		else
		{
			/* S_unarmed: do nothing */
		}
		return armed;
#endif
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	bool session<Handle, Allocator, Table, LockType>::undo_redo_pin_key(
		AK_ACTUAL
		allocator_type heap_
	)
	{
#if USE_CC_HEAP == 3
		AK_REF_VOID;
		(void) (heap_);
		return true;
#elif USE_CC_HEAP == 4
		auto &aspk = heap_.pool()->aspk();
		auto armed = aspk.is_armed();
		if ( armed )
		{
			/* _arm_ptr points to a new cptr, within a "large", within a persist_fixed_string */
			auto *pfs = key_type::pfs_from_cptr_ref(*aspk.arm_ptr());

			if ( aspk.was_callback_tested() )
			{
				/* S_uncommitted or S_committed: allocator had an allocation in "in_doubt" state,
				 * meaning that cptr, if not null contains an allocation address and not inline data
				 */
				if ( pfs->get_cptr().P )
				{
					/* S_committed: roll forward */
					pfs->pin(AK_REF aspk.get_cptr(), this->allocator());
				}
				else
				{
					/* S_uncommitted: roll back */
					pfs->set_cptr(aspk.get_cptr(), this->allocator());
				}
			}
			else
			{
				/* S_calling: allocator did not reach "in doubt" state, meaning that
				 * cptr contains null or old inline data.
				 */
				/* roll back */
				pfs->set_cptr(aspk.get_cptr(), this->allocator());
			}
			aspk.disarm(this->allocator());
		}
		else
		{
			/* S_unarmed: do nothing */
		}
		return armed;
#endif
	}

	/* session constructor and get_pool_regions only */
template <typename Handle, typename Allocator, typename Table, typename LockType>
	const Handle &session<Handle, Allocator, Table, LockType>::handle() const { return *this; }

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::insert(
		AK_ACTUAL
		const std::string &key,
		const void * value,
		const std::size_t value_len
	) -> std::pair<typename table_type::iterator, bool>
	{
		auto cvalue = static_cast<const char *>(value);

#if USE_CC_HEAP == 4
		/* Start of an emplace. Storage allocated by this->allocator()
		 * is to be disclaimed upon a restart unless
		 *  (1) verified in-use by the map (i.e., owner bit bit set to 1), or later
		 *  (2) forgotten by the tentative_allocation_state_emplace going out of scope, in which case the map bit has long since been set to 1.
		 */
		monitor_emplace<Allocator> m(this->allocator());
#endif
		++_writes;
		return
			map().emplace(
				AK_REF
				std::piecewise_construct
				, std::forward_as_tuple(AK_REF key.begin(), key.end(), this->allocator())
				, std::forward_as_tuple(
/* we wish that std::tuple had piecewise_construct, but it does not. */
#if 0
					std::piecewise_construct,
#endif
					std::forward_as_tuple(AK_REF cvalue, cvalue + value_len, this->allocator())
#if ENABLE_TIMESTAMPS
					, impl::tsc_now()
#endif
				)
			);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::update_by_issue_41(
		AK_ACTUAL
		const std::string &key,
		const void * value,
		const std::size_t value_len,
		void * /* old_value */,
		const std::size_t old_value_len
	)
	{
		definite_lock_type dl(AK_REF this->map(), key, _heap);

		/* hstore issue 41: "a put should replace any existing k,v pairs that match.
		 * If the new put is a different size, then the object should be reallocated.
		 * If the new put is the same size, then it should be updated in place."
		 */
		if ( value_len != old_value_len )
		{
			_atomic_state.enter_replace(
				AK_REF
				this->allocator()
				, &_map[pool_type::persist_data_type::ix_data]
				, key
				, static_cast<const char *>(value)
				, value_len
				, 0
				, std::tuple_element<0, mapped_type>::type::default_alignment /* requested default mapped_type alignment */
			);
		}
		else
		{
			std::vector<std::unique_ptr<component::IKVStore::Operation>> v;
			v.emplace_back(std::make_unique<component::IKVStore::Operation_write>(0, value_len, value));
			std::vector<component::IKVStore::Operation *> v2;
			std::transform(v.begin(), v.end(), std::back_inserter(v2), [] (const auto &i) { return i.get(); });
			this->atomic_update(AK_REF key, v2);
		}
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::get(
		const std::string &key,
		void* buffer,
		std::size_t buffer_size
	) const -> std::size_t
	{
		auto &v = map().at(key);
		auto value_len = std::get<0>(v).size();

		if ( value_len <= buffer_size )
		{
			std::memcpy(buffer, std::get<0>(v).data(), value_len);
		}
		return value_len;
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::get_alloc(
		const std::string &key
	) const -> std::tuple<void *, std::size_t>
	{
		auto &v = map().at(key);
		auto value_len = std::get<0>(v).size();

		auto value = ::scalable_malloc(value_len);
		if ( ! value )
		{
			throw std::bad_alloc();
		}

		std::memcpy(value, std::get<0>(v).data(), value_len);
		return std::pair<void *, std::size_t>(value, value_len);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::get_value_len(
		const std::string & key
	) const -> std::size_t
	{
		auto &v = this->map().at(key);
		return std::get<0>(v).size();
	}

#if ENABLE_TIMESTAMPS
template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::get_write_epoch_time(
		const std::string & key
	) const -> std::size_t
	{
		auto &v = this->map().at(key);
		// TO FIX
		//                      return impl::tsc_to_epoch(std::get<1>(v));
		return boost::numeric_cast<std::size_t>(impl::tsc_to_epoch(std::get<1>(v)).seconds());
	}
#endif

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::pool_grow(
		const std::unique_ptr<dax_manager> &dax_mgr_
		, const std::size_t increment_
	) const -> std::size_t
	{
		return this->pool()->grow(dax_mgr_, increment_);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::resize_mapped(
		AK_ACTUAL
		const std::string &key
		, std::size_t new_mapped_len
		, std::size_t alignment
	)
	{
		definite_lock_type dl(AK_REF this->map(), key, _heap);

		auto &v = this->map().at(key);
		auto &d = std::get<0>(v);
		/* Replace the data if the size changes or if the data should be realigned */
		if ( d.size() != new_mapped_len || reinterpret_cast<std::size_t>(d.data()) % alignment != 0 )
		{
			this->_atomic_state.enter_replace(
				AK_REF
				this->allocator()
				, &_map[pool_type::persist_data_type::ix_data]
				, key
				, d.data()
				, std::min(d.size(), new_mapped_len)
				, d.size() < new_mapped_len ? new_mapped_len - d.size() : std::size_t(0)
				, alignment
			);
		}
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::lock(
		AK_ACTUAL
		const std::string &key
		, lock_type type
		, void *const value
		, const std::size_t value_len
	) -> lock_result
	{
#if USE_CC_HEAP == 4
		monitor_emplace<Allocator> me(this->allocator());
#endif
		auto it = this->map().find(key);
		if ( it == this->map().end() )
		{
			/* if the key is not found
			 * we create it and allocate value space equal in size to
			 * value_len (but, as a special case, the creation is suppressed
			 * if value_len is 0).
			 */
			if ( value_len != 0 )
			{
				CPLOG(1, PREFIX "allocating object %zu bytes", LOCATION, value_len);

				++_writes;
				auto r =
					this->map().emplace(
						AK_REF
						std::piecewise_construct
						, std::forward_as_tuple(AK_REF fixed_data_location, key.begin(), key.end(), this->allocator())
						, std::forward_as_tuple(
/* we wish that std::tuple had piecewise_construct, but it does not. */
#if 0
							std::piecewise_construct,
#endif
							std::forward_as_tuple(AK_REF fixed_data_location, value_len, this->allocator())
#if ENABLE_TIMESTAMPS
							, impl::tsc_now()
#endif
						)
					);

				if ( ! r.second )
				{
					/* Should not happen. If we could not find it, should be able to create it */
					return { lock_result::e_state::creation_failed, component::IKVStore::KEY_NONE, value, value_len, nullptr };
				}

				auto &v = *r.first;
				auto &k = v.first;
				auto &m = v.second;
				auto &d = std::get<0>(m);
#if 0
				PLOG(PREFIX "data exposed (newly created): %p", LOCATION, d.data_fixed());
				PLOG(PREFIX "key exposed (newly created): %p", LOCATION, k.data_fixed());
#endif
				return {
					lock_result::e_state::created
					, try_lock(d, type)
						? new lock_impl(key)
						: component::IKVStore::KEY_NONE
					, d.data_fixed()
					, d.size()
					, k.data_fixed()
				};
			}
			else
			{
				return { lock_result::e_state::not_created, component::IKVStore::KEY_NONE, value, value_len, nullptr };
			}
		}
		else
		{
			auto &v = *it;
			const key_type &k = v.first;
			if ( ! k.is_fixed() )
			{
				auto &km = const_cast<typename std::remove_const<key_type>::type &>(k);
				monitor_pin_key<hstore_alloc_type<Persister>::heap_alloc_access_t> mp(km, _heap.pool());
				/* convert k to a immovable data */
				km.pin(AK_REF mp.get_cptr(), this->allocator());
			}
			mapped_type &m = v.second;
			auto &d = std::get<0>(m);
			/*
			 * "The complexity of software is an essential property, not an accidental one.
			 * Hence, descriptions of a software entity that abstract away its complexity
			 * often abstract away its essence." -- Fred Brooks, No Silver Bullet (1986)
			 */
			if( ! d.is_fixed() )
			{
				monitor_pin_data<hstore_alloc_type<Persister>::heap_alloc_access_t> mp(d, _heap.pool());
				/* convert d to a immovable data */
				d.pin(AK_REF mp.get_cptr(), this->allocator());
			}
#if 0
			PLOG(PREFIX "data exposed (extant): %p", LOCATION, d.data_fixed());
			PLOG(PREFIX "key exposed (extant): %p", LOCATION, k.data_fixed());
#endif
			/* Note: now returning E_LOCKED on lock failure as per a private request */
			lock_result r {
				lock_result::e_state::extant
				, try_lock(d, type)
					? new lock_impl(key)
					: component::IKVStore::KEY_NONE
				, d.data_fixed()
				, d.size()
				, k.data_fixed()
			};

#if ENABLE_TIMESTAMPS
			if ( type == component::IKVStore::STORE_LOCK_WRITE && r.key != component::IKVStore::KEY_NONE )
			{
				std::get<1>(m) = impl::tsc_now();
			}
#endif
			return r;
		}
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::unlock(component::IKVStore::key_t key_, component::IKVStore::unlock_flags_t flags_) -> status_t
	{
		if ( key_ )
		{
#if 0
			PINF(PREFIX "attempt unlock ...", LOCATION);
#endif
			if ( auto lk = dynamic_cast<lock_impl *>(key_) )
			{
#if 0
				PINF(PREFIX "attempt unlock %s", LOCATION, lk->key().c_str());
#endif
				try {
					auto &m = *this->map().find(lk->key());
					auto &v = std::get<1>(m);
					auto &d = std::get<0>(v);
					if ( flags_ & component::IKVStore::UNLOCK_FLAGS_FLUSH )
					{
						d.flush_if_locked_exclusive(this->allocator());
					}
					d.unlock();
				}
				catch ( const std::out_of_range &e )
				{
#if 0
					PINF(PREFIX "attempt unlock : key not found", LOCATION);
#endif
					return component::IKVStore::E_KEY_NOT_FOUND;
				}
				catch( ... ) {
					PLOG(PREFIX "attempt unlock : failed unexpected", LOCATION);
					throw General_exception(PREFIX "failed unexpectedly", __func__);
				}
				delete lk;
			}
			else
			{
				return E_INVAL; /* was not one of our locks */
			}
		}
		return S_OK;
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	bool session<Handle, Allocator, Table, LockType>::get_auto_resize() const
	{
		return this->map().get_auto_resize();
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::set_auto_resize(bool auto_resize)
	{
		this->map().set_auto_resize(auto_resize);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::erase(
		const std::string &key
	) -> status_t
	{
		auto it = this->map().find(key);
		if ( it != this->map().end() )
		{
			auto &v = *it;
			auto &m = v.second;
			auto &d = std::get<0>(m);
			if ( ! d.is_locked() )
			{
#if USE_CC_HEAP == 4
				monitor_emplace<Allocator> me(this->allocator());
#endif
				++_writes;
				map().erase(it);
				return S_OK;
			}
			else
			{
				return E_LOCKED;
			}
		}
		else
		{
			return component::IKVStore::E_KEY_NOT_FOUND;
		}
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::count() const -> std::size_t
	{
		return map().size();
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::bucket_count() const -> std::size_t
	{
		typename table_type::size_type count = 0;
		/* bucket counter */
		for (
			auto n = this->map().bucket_count()
			; n != 0
			; --n
		)
		{
			auto last = this->map().end(n-1);
			for ( auto first = this->map().begin(n-1); first != last; ++first )
			{
				++count;
			}
		}
		return count;
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::map(
		std::function
		<
			int(const void * key, std::size_t key_len,
			const void * val, std::size_t val_len)
		> function_
	) -> void
	{
		for ( auto &mt : this->map() )
		{
			const auto &pstring = mt.first;
			const auto &m = mt.second;
			const auto &d = std::get<0>(m);
			function_(
				reinterpret_cast<const void*>(pstring.data())
				, pstring.size()
				, d.data()
				, d.size()
			);
		}
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::map(
		std::function
		<
			int(const void * key
			, std::size_t key_len
			, const void * val
			, std::size_t val_len
			, common::tsc_time_t timestamp
			)
		> function_
		, common::epoch_time_t t_begin
		, common::epoch_time_t t_end
	) -> status_t
	{
#if ENABLE_TIMESTAMPS
		using raw_type = decltype(impl::epoch_to_tsc(t_begin).raw());
		auto begin_tsc = t_begin.is_defined() ? std::numeric_limits<raw_type>::min() : impl::epoch_to_tsc(t_begin).raw();
		auto end_tsc = t_end.is_defined() ? std::numeric_limits<raw_type>::max() : impl::epoch_to_tsc(t_end).raw();

		for ( auto &mt : this->map() )
		{
			const auto &pstring = mt.first;
			const auto &m = mt.second;
			const auto t = std::get<1>(m).raw();
#if 0
{
std::ostringstream s;
auto e = impl::tsc_to_epoch(std::get<1>(m));
s << "(hstore::session::map) (t_begin " << t_begin.seconds() << " ref.timestamp " << e.seconds() << " t_end " << t_end.seconds() << ") (begin_tsc " << begin_tsc << " t " << t << " end_tsc " << end_tsc << ")";
PLOG("%s", s.str().c_str());
}
#endif
			if ( begin_tsc <= t && t <= end_tsc )
			{
				function_(
					reinterpret_cast<const void*>(pstring.data())
					, pstring.size()
					, std::get<0>(m).data()
					, std::get<0>(m).size()
					, impl::tsc_to_epoch(std::get<1>(m))
				);
			}
		}
		return S_OK;
#else
		(void) function_;
		(void) t_begin;
		(void) t_end;
		return E_FAIL;
#endif
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::atomic_update_inner(
		AK_ACTUAL
		const std::string &key
		, const std::vector<component::IKVStore::Operation *> &op_vector
	)
	{
		_atomic_state.enter_update(AK_REF this->allocator(), &_map[pool_type::persist_data_type::ix_data], key, op_vector.begin(), op_vector.end());
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::atomic_update(
		AK_ACTUAL
		const std::string& key
		, const std::vector<component::IKVStore::Operation *> &op_vector
	)
	{
		this->atomic_update_inner(AK_REF key, op_vector);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::lock_and_atomic_update(
		AK_ACTUAL
		const std::string& key
		, const std::vector<component::IKVStore::Operation *> &op_vector
	)
	{
		definite_lock_type m(AK_REF this->map(), key, _heap.pool());
		this->atomic_update_inner(AK_REF key, op_vector);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void *session<Handle, Allocator, Table, LockType>::allocate_memory(
		AK_ACTUAL
		std::size_t size
		, std::size_t alignment
	)
	{
		persistent_t<char *> p = nullptr;
		/* ERROR: leaks memory on a crash */
		allocator().allocate_tracked(AK_REF p, size, clean_align(alignment, sizeof(void *)));
		return p;
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::free_memory(
		const void* addr
		, size_t size
	)
	{
		persistent_t<char *> p = static_cast<char *>(const_cast<void *>(addr));
#if USE_CC_HEAP == 4
		/* ERROR: leaks memory on a crash */
#endif
		allocator().deallocate_tracked(p, size);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	void session<Handle, Allocator, Table, LockType>::flush_memory(
		const void* addr
		, size_t size
	)
	{
		persistent_t<char *> p = static_cast<char *>(const_cast<void *>(addr));
            CPLOG(2, "%s: %p %zx", __func__, addr, size);
		allocator().persist(p, size);
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	unsigned session<Handle, Allocator, Table, LockType>::percent_used() const
	{
		return this->pool()->percent_used();
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::swap_keys(
		AK_ACTUAL
		const std::string &key0
		, const std::string &key1
	) -> status_t
	try
	{
		definite_lock_type d0(AK_REF this->map(), key0, _heap.pool());
		definite_lock_type d1(AK_REF this->map(), key1, _heap.pool());

		_atomic_state.enter_swap(
			d0.mapped()
			, d1.mapped()
		);

		return S_OK;
	}
	catch ( const std::domain_error & )
	{
		return component::IKVStore::E_KEY_NOT_FOUND;
	}
	catch ( const std::range_error & )
	{
		return E_LOCKED;
	}


template <typename Handle, typename Allocator, typename Table, typename LockType>
	auto session<Handle, Allocator, Table, LockType>::open_iterator() -> component::IKVStore::pool_iterator_t
	{
		auto i = std::make_shared<pool_iterator_type>(this->writes(), this->map().cbegin(), this->map().cend() );
		_iterators.insert({i.get(), i});
		return i.get();
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	status_t session<Handle, Allocator, Table, LockType>::deref_iterator(
		component::IKVStore::pool_iterator_t iter
		, const common::epoch_time_t t_begin
		, const common::epoch_time_t t_end
		, component::IKVStore::pool_reference_t & ref
		, bool& time_match
		, bool increment
	)
	{
		auto i = static_cast<pool_iterator_type *>(iter);
		if ( _iterators.count(i) != 1 )
		{
			return E_INVAL;
		}

		if ( i->is_end() )
		{
			return E_OUT_OF_BOUNDS;
		}

		if ( ! i->check_mark(_writes) )
		{
			return E_ITERATOR_DISTURBED;
		}

#if ENABLE_TIMESTAMPS
		using raw_type = decltype(impl::epoch_to_tsc(t_begin).raw());
		auto begin_tsc = t_begin.is_defined() ? std::numeric_limits<raw_type>::min() : impl::epoch_to_tsc(t_begin);
		auto end_tsc = t_end.is_defined() ? std::numeric_limits<raw_type>::max() : impl::epoch_to_tsc(t_end);
#else
		(void)t_begin;
		(void)t_end;
#endif

		auto &r = i->_iter;
		{
			const auto &k = r->first;
			ref.key = k.data();
			ref.key_len = k.size();
		}
		{
			const auto &m = r->second;
			const auto &d = std::get<0>(m);
			ref.value = d.data();
			ref.value_len = d.size();
#if ENABLE_TIMESTAMPS
			const auto t = std::get<1>(m);
			ref.timestamp = impl::tsc_to_epoch(t);
#if 0
{
std::ostringstream s;
s << "(hstore::session::dref_iterator) (t_begin " << t_begin.seconds() << " ref.timestamp " << ref.timestamp.seconds() << " t_end " << t_end.seconds() << ") (begin_tsc " << begin_tsc << " t " << t << " end_tsc " << end_tsc << ")";
PLOG("%s", s.str().c_str());
}
#endif
			time_match = ( begin_tsc <= t && t <= end_tsc );
#endif
		}

		if ( increment )
		{
			++r;
		}

		return S_OK;
	}

template <typename Handle, typename Allocator, typename Table, typename LockType>
	status_t session<Handle, Allocator, Table, LockType>::close_iterator(component::IKVStore::pool_iterator_t iter)
	{
		if ( iter == nullptr )
		{
			return E_INVAL;
		}
		auto i = static_cast<pool_iterator_type *>(iter);
		if ( _iterators.erase(i) != 1 )
		{
			return E_INVAL;
		}
		return S_OK;
	}
