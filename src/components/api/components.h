/*
   Copyright [2017-2019] [IBM Corporation]
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
#ifndef __COMANCHE_COMPONENTS_H__
#define __COMANCHE_COMPONENTS_H__

#include <component/base.h>
/* Note: these uuid decls are so we don't have to have access to the component
 * source code */

#include "itf_ref.h"
#include "types.h"

// clang-format off

namespace component
{
/*< used as any designator */
DECLARE_STATIC_COMPONENT_UUID(any_component, 0xffffffff, 0xffff, 0xffff, 0xffff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff);

/*< fabric */
DECLARE_STATIC_COMPONENT_UUID(net_fabric, 0x8b93a5ae, 0xcf34, 0x4aff, 0x8321, 0x19, 0x08, 0x21, 0xa9, 0x9f, 0xd3);
DECLARE_STATIC_COMPONENT_UUID(net_fabric_factory, 0xfac3a5ae, 0xcf34, 0x4aff, 0x8321, 0x19, 0x08, 0x21, 0xa9, 0x9f, 0xd3);

/*< hstore, hash based persistent store */
DECLARE_STATIC_COMPONENT_UUID(hstore, 0x1f1bf8cf, 0xc2eb, 0x4710, 0x9bf1, 0x63, 0xf5, 0xe8, 0x1a, 0xcf, 0xbd);
DECLARE_STATIC_COMPONENT_UUID(hstore_factory, 0xfacbf8cf, 0xc2eb, 0x4710, 0x9bf1, 0x63, 0xf5, 0xe8, 0x1a, 0xcf, 0xbd);

/*< map store */
DECLARE_STATIC_COMPONENT_UUID(mapstore, 0x8a120985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x21);
DECLARE_STATIC_COMPONENT_UUID(mapstore_factory, 0xfac20985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x21);

/*< ramrbtree index*/
DECLARE_STATIC_COMPONENT_UUID(rbtreeindex, 0x8a120985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x29);
DECLARE_STATIC_COMPONENT_UUID(rbtreeindex_factory, 0xfac20985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x29);

/*< mcas client */
DECLARE_STATIC_COMPONENT_UUID(mcas_client, 0x2f666078, 0xcb8a, 0x4724, 0xa454, 0xd1, 0xd8, 0x8d, 0xe2, 0xdb, 0x87);
DECLARE_STATIC_COMPONENT_UUID(mcas_client_factory, 0xfac66078, 0xcb8a, 0x4724, 0xa454, 0xd1, 0xd8, 0x8d, 0xe2, 0xdb, 0x87);

/*< ADO manager proxy */
DECLARE_STATIC_COMPONENT_UUID(ado_manager_proxy, 0x8a120985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x91);
DECLARE_STATIC_COMPONENT_UUID(ado_manager_proxy_factory, 0xfac20985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x91);

/*< ADO proxy */
DECLARE_STATIC_COMPONENT_UUID(ado_proxy, 0x8a120985, 0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x92);
DECLARE_STATIC_COMPONENT_UUID(ado_proxy_factory, 0xfac20985,  0x1253, 0x404d, 0x94d7, 0x77, 0x92, 0x75, 0x21, 0xa1, 0x92);

/*< TLS Crypto component */
DECLARE_STATIC_COMPONENT_UUID(tls, 0x8c4636c7, 0x84bd, 0x4f88, 0xa6a8, 0x98, 0x53, 0x65, 0x4b, 0xc4, 0xbd);
DECLARE_STATIC_COMPONENT_UUID(tls_factory, 0xfac636c7, 0x84bd, 0x4f88, 0xa6a8, 0x98, 0x53, 0x65, 0x4b, 0xc4, 0xbd);

/*< zyre */
DECLARE_STATIC_COMPONENT_UUID(cluster_zyre,0x5d19463b,0xa29d,0x4bc1,0x989c,0xbe,0x74,0x0a,0xc2,0x79,0x10);
DECLARE_STATIC_COMPONENT_UUID(cluster_zyre_factory,0xfac9463b,0xa29d,0x4bc1,0x989c,0xbe,0x74,0x0a,0xc2,0x79,0x10);

}  // namespace component

// clang-format on

#endif  // __COMPONENTS_H__