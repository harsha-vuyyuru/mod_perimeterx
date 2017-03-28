#!/bin/bash

sed -i 's@AppId@AppId '"$APP_ID"'@' /home/r/mod_perimeterx/t/conf/extra.conf.in
sed -i 's@AuthToken@AuthToken '"$AUTH_TOKEN"'@' /home/r/mod_perimeterx/t/conf/extra.conf.in

/home/r/mod_perimeterx/t/TEST -v
