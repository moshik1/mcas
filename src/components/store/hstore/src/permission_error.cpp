/*
   Copyright [2020-2021] [IBM Corporation]
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

#include "access.h"

namespace
{
	const char *map_name(std::size_t ix_)
	{
		return
			ix_ == 0 ? "control"
			: ix_ == 1 ? "data"
			: "(invalid)"
			;
	}

	std::string perm_string(unsigned perm_)
	{
		return
			std::string(perm_ & impl::access::read ? "r" : "-")
				.append(1, perm_ & impl::access::write ? 'w' : '-')
				.append(1, perm_ & impl::access::list ? 'l' : '-')
			;
	}
}

impl::permission_error::permission_error(
	std::size_t ix_, unsigned have_, unsigned need_
)
	: std::runtime_error(std::string("permission error: mep ") + map_name(ix_) + " have " + perm_string(have_) + " need " + perm_string(need_))
{}
