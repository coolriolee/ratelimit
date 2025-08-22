# ratelimit
    lan ip speed limit with ebpf tc[ipv4+ipv6]

    限速参考cilium EDT(Earliest Departure Time)

## 1、编译 && 部署

    mkdir builddir && cd builddir

    cmake -DCMAKE_BUILD_TYPE=Release ../src/

    make && make install

## 2、配置 && 运行
    示例：监听的内网网口为ens33，待限速的内网终端为192.168.1.2，终端下行限速50mbps 上行限速10mbps

    #将ebpf tc程序附加到ens33网卡上 [tc egress/ingress]
    /ratelimit/bin/ratelimit.sh addtap ens33

    #配置指定内网终端的限速规则
    /ratelimit/bin/ratelimit add 192.168.1.2 50000000 10000000

    #查看指定内网终端的限速规则
    /ratelimit/bin/ratelimit show 192.168.1.2

    #删除指定内网终端限速
    /ratelimit/bin/ratelimit del 192.168.1.2

## 说明
    #配置限速的可执行程序
    ratelimit

    #用于附加到网卡的ebpf tc程序[当前仓库的版本基于x86_64 ubuntu22.04 kernel:5.19.0-43-generic]
    ratelimit_kern.o

    #将ebpf tc程序附加/卸载网卡的配置脚本
    ratelimit.sh 

## 特别鸣谢
-[cilium](https://github.com/cilium/cilium.git/)