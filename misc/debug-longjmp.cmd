file uftrace
set breakpoint pending on

b setup_jmpbuf_rstack
#b command_record
catch exec
commands
#  set follow-fork-mode child
  b main
  continue
end

# r record -L. -d xxx --keep-pid --force tests/t-abc

r -L. --keep-pid --force tests/t-longjmp 