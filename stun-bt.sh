# 以下变量需按要求填写
IFNAME=					# 指定接口，可留空；仅在多 WAN 时需要；拨号接口的格式为 "pppoe-wancm"
GWLADDR=192.168.1.1		# 主路由 LAN 的 IPv4 地址
APPADDR=192.168.1.168	# 下载设备的 IPv4 地址，允许主路由或旁路由本身运行 BT 应用
APPPORT=12345			# BT 应用的监听端口，HTTP 改包要求 5 位数端口

WANADDR=$1
WANPORT=$2
LANPORT=$4
L4PROTO=$5
OWNADDR=$6
STUNIFO=/tmp/stun-bt.info
OLDPORT=$(grep $L4PROTO $STUNIFO 2>/dev/null | awk -F ':| ' '{print$3}')
RELEASE=$(grep ^ID= /etc/os-release | awk -F '=' '{print$2}' | tr -d \")

# 判断 TCP 或 UDP 的穿透是否启用
# 清理穿透信息中没有运行的协议
touch $STUNIFO
case $RELEASE in
	openwrt)
		for SECTION in $(uci show natmap | grep $0 | awk -F . '{print$2}'); do
			if [ "$(uci -q get natmap.$SECTION.enable)" = 1 ]; then
				case $(uci get natmap.$SECTION.udp_mode) in
					0) SECTTCP=$SECTION ;;
					1) SECTUDP=$SECTION ;;
				esac
			fi
		done
		[ $(uci -q get natmap.$SECTTCP) ] || ( \
		DISPORT="$(grep tcp $STUNIFO | awk -F ':| ' '{print$3}') tcp"; sed -i '/'tcp'/d' $STUNIFO )
		[ $(uci -q get natmap.$SECTUDP) ] || ( \
		DISPORT="$(grep udp $STUNIFO | awk -F ':| ' '{print$3}') udp"; sed -i '/'udp'/d' $STUNIFO )
		;;
	*)
		ps aux | grep $0 | grep "\-h" || ( \
		DISPORT="$(grep tcp $STUNIFO | awk -F ':| ' '{print$3}') tcp"; sed -i '/'tcp'/d' $STUNIFO )
		ps aux | grep $0 | grep "\-u" || ( \
		DISPORT="$(grep udp $STUNIFO | awk -F ':| ' '{print$3}') udp"; sed -i '/'udp'/d' $STUNIFO )
		;;
esac

# 更新保存穿透信息
sed -i '/'$L4PROTO'/d' $STUNIFO
echo $L4PROTO $WANADDR:$WANPORT '->' $OWNADDR:$LANPORT '->' $APPADDR:$APPPORT $(date +%s) >>$STUNIFO

# 防止脚本同时操作 nftables 导致冲突
[ $L4PROTO = udp ] && sleep 1 && \
[ $(($(date +%s) - $(grep tcp $STUNIFO | awk '{print$NF}'))) -lt 2 ] && sleep 2

# 初始化
nft add table ip STUN
nft delete chain ip STUN BTTR 2>/dev/null
nft create chain ip STUN BTTR { type filter hook postrouting priority filter \; }
WANTCP=$(grep tcp $STUNIFO | awk -F ':| ' '{print$3}')
WANUDP=$(grep udp $STUNIFO | awk -F ':| ' '{print$3}')
if [ -n "$IFNAME" ]; then
	IIFNAME="iifname $IFNAME"
	OIFNAME="oifname $IFNAME"
fi

# HTTP Tracker
STRTCP=$(printf 30$(printf "$WANTCP" | xxd -p) | tail -c 10)
STRUDP=$(printf 30$(printf "$WANUDP" | xxd -p) | tail -c 10)
if [ -n "$WANTCP" ] && [ -n "$WANUDP" ]; then
	SETSTR="numgen inc mod 2 map { 0 : 0x3d$STRTCP, 1 : 0x3d$STRUDP }"
elif [ -n "$WANTCP" ]; then
	SETSTR=0x3d$STRTCP
elif [ -n "$WANUDP" ]; then
	SETSTR=0x3d$STRUDP
fi
nft add set ip STUN BTTR_HTTP "{ type ipv4_addr . inet_service; flags dynamic; timeout 1h; }"
nft add chain ip STUN BTTR_HTTP
nft flush chain ip STUN BTTR_HTTP
nft insert rule ip STUN BTTR $OIFNAME ip saddr $APPADDR ip daddr . tcp dport @BTTR_HTTP counter goto BTTR_HTTP
nft add rule ip STUN BTTR $OIFNAME ip saddr $APPADDR meta l4proto tcp @ih,0,112 0x474554202f616e6e6f756e63653f add @BTTR_HTTP { ip daddr . tcp dport } counter goto BTTR_HTTP
for OFFSET in $(seq 768 16 1040); do
	nft add rule ip STUN BTTR_HTTP @ih,$OFFSET,40 0x706f72743d @ih,$(($OFFSET+32)),48 set $SETSTR update @BTTR_HTTP { ip daddr . tcp dport } counter accept
done

# UDP Tracker
if [ -n "$WANTCP" ] && [ -n "$WANUDP" ]; then
	SETNUM="numgen inc mod 2 map { 0 : $WANTCP, 1 : $WANUDP }"
elif [ -n "$WANTCP" ]; then
	SETNUM=$WANTCP
elif [ -n "$WANUDP" ]; then
	SETNUM=$WANUDP
fi
nft add set ip STUN BTTR_UDP "{ type ipv4_addr . inet_service; flags dynamic; timeout 1h; }"
nft add chain ip STUN BTTR_UDP
nft flush chain ip STUN BTTR_UDP
nft insert rule ip STUN BTTR $OIFNAME ip saddr $APPADDR ip daddr . udp dport @BTTR_UDP counter goto BTTR_UDP
nft add rule ip STUN BTTR $OIFNAME ip saddr $APPADDR meta l4proto udp @ih,0,64 0x41727101980 @ih,64,32 0 add @BTTR_UDP { ip daddr . udp dport } counter goto BTTR_UDP
nft add rule ip STUN BTTR_UDP @ih,64,32 1 @ih,768,16 $APPPORT @ih,768,16 set $SETNUM update @BTTR_UDP { ip daddr . udp dport } counter

# 判断脚本运行的环境，选择 DNAT 方式
# 先排除需要 UPnP 的情况
DNAT=0
for LANADDR in $(ip -4 a show dev br-lan | grep inet | awk '{print$2}' | awk -F '/' '{print$1}'); do
	[ "$LANADDR" = $GWLADDR ] && DNAT=1
done
for LANADDR in $(nslookup -type=A $HOSTNAME | grep Address | grep -v :53 | awk '{print$2}'); do
	[ "$LANADDR" = $GWLADDR ] && DNAT=1
done
[ $APPADDR = $GWLADDR ] && DNAT=2

# 若未排除，则尝试直连 UPnP
if [ $DNAT = 0 ]; then
	[ -n "$OLDPORT" ] && upnpc -i -d $OLDPORT $L4PROTO
	[ -n "$DISPORT" ] && upnpc -i -d $DISPORT
	upnpc -i -e "STUN BT $L4PROTO $WANPORT->$LANPORT->$APPPORT" -a $APPADDR $APPPORT $LANPORT $L4PROTO | \
	grep $APPADDR | grep $APPPORT | grep $LANPORT | grep -v failed
	[ $? = 0 ] && DNAT=3
fi

# 直连失败，则尝试代理 UPnP
if [ $DNAT = 0 ]; then
	PROXYCONF=/tmp/proxychains.conf
	echo [ProxyList] >$PROXYCONF
	echo http $APPADDR 3128 >>$PROXYCONF
	[ -n "$OLDPORT" ] && proxychains -f $PROXYCONF upnpc -i -d $OLDPORT $L4PROTO
	[ -n "$DISPORT" ] && proxychains -f $PROXYCONF upnpc -i -d $DISPORT
	proxychains -f $PROXYCONF \
	upnpc -i -e "STUN BT $L4PROTO $WANPORT->$LANPORT->$APPPORT" -a $APPADDR $APPPORT $LANPORT $L4PROTO | \
	grep $APPADDR | grep $APPPORT | grep $LANPORT | grep -v failed
	[ $? = 0 ] && DNAT=3
fi

# 代理失败，则启用本机 UPnP
[ $DNAT = 0 ] && upnpc -i -e "STUN BT $L4PROTO $WANPORT->$LANPORT" -a @ $LANPORT $LANPORT $L4PROTO

# 初始化 DNAT 链
if [ $DNAT != 3 ]; then
	[ -z "$WANTCP" ] && nft delete chain ip STUN BTDNAT_tcp 2>/dev/null
	[ -z "$WANUDP" ] && nft delete chain ip STUN BTDNAT_udp 2>/dev/null
	nft delete chain ip STUN BTDNAT_$L4PROTO 2>/dev/null
	nft create chain ip STUN BTDNAT_$L4PROTO { type nat hook prerouting priority dstnat \; }
fi

# BT 应用运行在路由器下，使用 dnat
if [ $DNAT = 1 ]; then
	nft add rule ip STUN BTDNAT_$L4PROTO $IIFNAME $L4PROTO dport $LANPORT counter dnat ip to $APPADDR:$APPPORT
	if ! nft list chain inet fw4 forward | grep 'ct status dnat' >/dev/null; then
		HANDLE=$(nft -a list chain inet fw4 forward | grep jump | awk 'NR==1{print$NF}')
		nft insert rule inet fw4 forward handle $HANDLE ct status dnat counter accept
	fi
fi

# BT 应用运行在路由器上，使用 redirect
if [ $DNAT = 2 ]; then
	nft add rule ip STUN BTDNAT_$L4PROTO $IIFNAME $L4PROTO dport $LANPORT counter redirect to :$APPPORT
	if ! nft list chain inet fw4 input | grep 'ct status dnat' >/dev/null; then
		HANDLE=$(nft -a list chain inet fw4 input | grep jump | awk 'NR==1{print$NF}')
		nft insert rule inet fw4 input handle $HANDLE ct status dnat counter accept
	fi
fi
