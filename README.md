# memory_monitor
Limit a process group to a certain amount of memory.  Kill and restart processes over the limit.  

This program was born out of a dilemma.  I had a set of Ceph servers that didn't have enough ram on them for a recovery process.  We didn't want to buy more ram because the servers were going to be decommissioned soon.  So I tried adding a bunch of swap to the systems but that was terrible.  So I wondered if Ceph could make progress if the ceph-osd process was killed everytime it went over a certain limit.  
