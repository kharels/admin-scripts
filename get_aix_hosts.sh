for m in $(lssyscfg -r sys -F name); do printf "\n=== $m ===\n" ; \
                                                     lssyscfg -r lpar -m $m -F lpar_id:name:state | sort -n ; done
