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

#ifndef MCAS_HSTORE_POOL_ITERATOR_H
#define MCAS_HSTORE_POOL_ITERATOR_H

#include <api/kvstore_itf.h> /* component::IKVStore::Opaque_pool_iterator */

#include <cstdint> /* uint64_t */

template <typename Handle, typename Allocator, typename Table, typename LockType>
	struct session;

template <typename Table>
	struct pool_iterator
		: public component::IKVStore::Opaque_pool_iterator
	{
	private:
		using table_t = Table;
		std::uint64_t _mark;
		typename table_t::const_iterator _end;
	public:
		typename table_t::const_iterator _iter;
	public:
		template <typename Handle, typename Allocator, typename LockType>
			explicit pool_iterator(
				const session<Handle, Allocator, Table, LockType> * session_
			);

		bool is_end() const;
		bool check_mark(std::uint64_t writes) const;
	};

#include "pool_iterator.tcc"

#endif
