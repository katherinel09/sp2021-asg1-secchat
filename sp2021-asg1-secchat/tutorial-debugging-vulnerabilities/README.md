# 
#  We have a series of simple programs vulnerable to some specific type of
#  attacks:
#  a) simple_overflow.c (stack based overflow that leads to priviledge escalation)
#  b) simple_cp_hijack.c (heap based overflow that leads to code pointer hijacking)
#  c) simple_leak.c (uninitialized read through a structure's padding that leads 
#                   to a memory leak)
#  d) simple_heap_leak.c (uninitialized read on the heap that leads to a memory leak)
#  e) simple_mem_leak.c (heap leak that either exhaust the virtual memory of the 
#                        program or even the physical memory).
#  f) simple_double_free.c (simple exploitable double free error).
#  g) simple_heap_metadata_corruption.c (simple heap metadata corruption)
#  
#  Additionally we have two more program examples of working with ltrace/strace
#  and valgrind.
#  a) strace_lstrace_fun.c (working with ltrace/strace).
#  b) memory_errors.c (working with valgrind).
# 
#  @NOTES: at the beginning of each .c file you will find explanations, hints and
#          tips on how to work/exploit the specific program. 
# 
#  AddressSpace.png is a print screen of the memory address we were using in the
#  tutorial. The .ogv file shows an example execution of program e) (in case you
#  don't want your laptop to hang during the test watch the video.
#  




