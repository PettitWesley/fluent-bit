set(src
  stdout.c
  s3_local_buffer.c)

FLB_PLUGIN(out_stdout "${src}" "")
