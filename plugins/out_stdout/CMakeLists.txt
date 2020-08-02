set(src
  stdout.c
  s3_multipart.c)

FLB_PLUGIN(out_stdout "${src}" "")
