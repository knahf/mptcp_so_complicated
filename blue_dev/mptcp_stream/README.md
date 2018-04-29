to build and install into snort installation ... 

1) set $my_path to point to snort3 installation
  e.g. ~/snort_bin   or wherever you installed snort3 to. 

2) mkdir -p build

3) cd build

4) cmake -DCMAKE_INSTALL_PREFIX=$my_path ..

5) make ; make install 

6) should also compile the python module used by mpr_server.py 
   in the proto/ directory.
   ```bash
   protoc --python_out=./proto proto/seg_xfer.proto
   ```
    In order to have snort use it, edit the $my_path/etc/snort/snort.lua file to have it enabled
   e.g. add this line at the end of the list of built in plugins
    
    ``` 
    'mptcp_stream = { }' 
    ```

    For it to work, the python reassembly server needs to be running...
    ```bash
    python3 mpr_server.py 
    ```


Finally, here's what an invocation to test it out against a file would look like if your current directory is the root of the repo (where the pcap/ directory is)
```
$my_path/bin/snort -c $my_path/etc/snort/snort.lua  --plugin-path $my_path/lib -r pcaps/chapter3_pcaps/ch3scenario3test1.pcapng -A alert_fast -R $my_path/etc/snort/test.rules 
```

`-c` specifies the config (this is where you tell snort3 to use the plugin) 

`-r` tells snort to replay a pcap file 

`-A` alert_fast will print out alerts directly to the console

`-R` is used to specify a rules file. 
To generate alerts from the given pcap, create a test.rules with the following rule in it: 

```
alert tcp any any -> any any (content:"FIREFIREFIRE"; msg:"FIREx3"; sid:10000001;)
```

It will be obvious that **everything is very buggy** (for instance, once a matching signature has been seen it continues to generate alerts for every subsequent packet in the flow). 

