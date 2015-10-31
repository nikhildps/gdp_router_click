//gdp_router_secondary_1.click
//an example of an S node
//SADDR - link interface of the router (eg eth0 or 128.32.33.47)
//SPORT - listening port of the router
//BOOTADDR - address of a P node already in the network
//BOOTPORT - port of an existing P node in the network
//CANBEPROXY - boolean option wether the router can serve as proxy or not (true or false)
//           (for S nodes this option's value doesnt matter)
//WPORT - port of the http server running inside router to display statistics in visualization tool

define($SADDR eth0, $SPORT 8988, $BOOTADDR 128.32.33.68, $BOOTPORT 7788, $CANBEPROXY false, $WPORT 14000)

gdp :: GDPRouterNat($SADDR, $SPORT, $BOOTADDR, $BOOTPORT, $CANBEPROXY, $WPORT)