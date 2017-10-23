file uftrace
set breakpoint pending on

b mcount_get_arg
#b command_record
catch exec
commands
#  set follow-fork-mode child
  b main
  continue
end

# r record -L. -d xxx --keep-pid --force tests/t-abc

r --keep-pid --force -L. -A "^int_@arg1,arg2" tests/t-exp-int 
