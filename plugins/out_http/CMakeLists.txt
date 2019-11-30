set(src
  http.c
  http_conf.c
  )

# find_package(aws-c-http REQUIRED)
# find_package(aws-c-mqtt REQUIRED)
# find_package(aws-c-cal REQUIRED)
# find_package(aws-c-auth REQUIRED)
# target_link_libraries(${CMAKE_PROJECT_NAME} AWS::aws-c-auth AWS::aws-c-cal AWS::aws-c-http AWS::aws-c-mqtt)

FLB_PLUGIN(out_http "${src}" "mk_core")
