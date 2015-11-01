//gdp_router_primary_no_proxy.click
//an example of a P node that doesnt want to serve as a proxy
//SADDR - link interface of the router (eg eth0 or 128.32.33.47)
//SPORT - listening port of the router
//BOOTADDR - address of a P node already in the network
//           for the first node, SADDR = BOOTADDR
//BOOTPORT - port of an existing P node in the network
//           for the first node, SPORT = BOOTPORT
//CANBEPROXY - boolean option wether the router can serve as proxy or not (true or false)
//WPORT - port of the http server running inside router to display statistics in visualization tool
//DEBUG - option to print router's debug output on terminal (1 or 0)

define($SADDR 128.32.33.47, $SPORT 8988, $BOOTADDR 128.32.33.68, $BOOTPORT 7788, $CANBEPROXY false, $WPORT 14000, $DEBUG 1)

gdp :: GDPRouterNat($SADDR, $SPORT, $BOOTADDR, $BOOTPORT, $CANBEPROXY, $WPORT, $DEBUG)