#!/bin/sh
cd `dirname $0`
ROOT_PATH=`pwd`
java -Xms256M -Xmx1024M -cp .:$ROOT_PATH:$ROOT_PATH/../lib/routines.jar:$ROOT_PATH/../lib/log4j-1.2.16.jar:$ROOT_PATH/../lib/dom4j-1.6.1.jar:$ROOT_PATH/../lib/talendcsv.jar:$ROOT_PATH/../lib/talend_file_enhanced_20070724.jar:$ROOT_PATH/../lib/jtds-1.3.1-patch.jar:$ROOT_PATH/call_tos_0_1.jar: bboradoli.call_tos_0_1.CALL_TOS --context=Default "$@" 