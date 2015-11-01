//gdp_router_secondary_2.click
//a second example of an S node
//SADDR - link interface of the router (eg eth0 or 128.32.33.47)
//SPORT - listening port of the router
//BOOTADDR - address of a P node already in the network
//BOOTPORT - port of an existing P node in the network
//CANBEPROXY - boolean option wether the router can serve as proxy or not (true or false)
//            (for S nodes this option's value doesnt matter)
//WPORT - port of the http server running inside router to display statistics in visualization tool
//DEBUG - option to print router's debug output on terminal (1 or 0)

define($SADDR 10.0.0.1, $SPORT 8988, $BOOTADDR 128.32.33.68, $BOOTPORT 7788, $CANBEPROXY true, $WPORT 14000, $DEBUG 1)

gdp :: GDPRouterNat($SADDR, $SPORT, $BOOTADDR, $BOOTPORT, $CANBEPROXY, $WPORT, $DEBUG)