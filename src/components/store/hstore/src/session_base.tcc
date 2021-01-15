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

#include "permission_error.h"

template <typename Handle>
	const std::string session_base<Handle>::ac_prefix = "ac.";

template <typename Handle>
	session_base<Handle>::session_base(
		Handle &&pop_
		, unsigned debug_level_
	)
		: Handle(std::move(pop_))
		, common::log_source(debug_level_)
		, _writes(0)
		, _access_allowed{}
	{}

template <typename Handle>
	auto session_base<Handle>::map_ix(const string_view key_, impl::access::access_type access_required_) const -> std::size_t
    {
		std::size_t ix =
			key_.find(ac_prefix.data(), 0, ac_prefix.size()) == 0
			? pool_type::persist_data_type::ix_control
			: pool_type::persist_data_type::ix_data
			;

		if ( ( _access_allowed[ix] & access_required_ ) != access_required_ )
		{
			throw impl::permission_error(ix, _access_allowed[ix], access_required_);
		}

		return ix;
	}
