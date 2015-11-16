//gdp_router_bootstrap.click
//The very first router node to join the network
//SADDR - link interface of the router (eg eth0 or 128.32.33.68)
//SPORT - listening port of the router
//BOOTADDR - address of a P node already in the network
//           for the first node, SADDR = BOOTADDR
//BOOTPORT - port of an existing P node in the newtrok
//           for the first node, SPORT = BOOTPORT
//CANBEPROXY - boolean option wether the router can serve as proxy or not (true or false)
//WPORT - port of the http server running inside router to display statistics in visualization tool
//DEBUG - option to print router's debug output on terminal (1 or 0)
 
define($SADDR 128.32.33.68, $SPORT 8007, $BOOTADDR 128.32.33.68, $BOOTPORT 8007, $CANBEPROXY true, $WPORT 15000, $DEBUG 1)

gdp :: GDPRouterNat($SADDR, $SPORT, $BOOTADDR, $BOOTPORT, $CANBEPROXY, $WPORT, $DEBUG)