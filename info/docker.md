# Deploy and Run MCAS inside Container

Like ADO process, MCAS server can also run on bare-metal on-prem and also within a container. This documents shows how to build and run MCAS server inside container. Note this is different from [ADO Docker Containerization](./ado-docker.md) which only launches ADO process inside container.

## Setup Docker Environment
- Follow [instructions](https://docs.docker.com/install/linux/docker-ce/ubuntu/) to install
docker.

- Add yourself into docker group for no-root execution.

## Setup host kernel module
Follow [Quick Start](./quick_start.md) through System Configuraiton to isntall kernel modules ```xpmem.ko``` and ```mcasmod```.

## Build Docker Image for MCAS (Optional if you do not have access to registry):
- Build image:
```bash
docker build -f $MCAS_HOME/deploy/kubernetes/Dockerfile.mcas -t res-mcas-docker-local.artifactory.swg-devops.com/mcas:latest $MCAS_HOME
  ```
- (Optional) Push image:
```bash
docker push res-mcas-docker-local.artifactory.swg-devops.com/mcas:latest
```

## Run MCAS Docker Image:
- If running with RDMA:
```bash
docker run --rm -it --privileged --cap-add=ALL -v /dev:/dev -v /lib/modules:/lib/modules --net=host --device=/dev/infiniband/uverbs0 --device=/dev/infiniband/rdma_cm --ulimit memlock=-1 res-mcas-docker-local.artifactory.swg-devops.com/mcas:latest bash
```

- If running with standard socket:
```bash
docker run --rm -it --privileged --cap-add=ALL -v /dev:/dev -v /lib/modules:/lib/modules --ulimit memlock=-1 res-mcas-docker-local.artifactory.swg-devops.com/mcas:latest bash
```

After getting in the bash, your mcas binary is located in ```/mcas/build/dist```. Then you can continue following  [Quick Start](./quick_start.md) to launch MCAS server. Another container can be launched as client with the same command as server. See [Kubernetes](./kubernetes.md) for deploying containers on a kubernetes cluster (different nodes).

